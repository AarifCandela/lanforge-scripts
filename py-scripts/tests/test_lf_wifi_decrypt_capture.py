"""Check capture rewriting with synthetic records and no real session keys."""
from contextlib import closing
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib


MODULE = Path(__file__).resolve().parents[1] / "lf_wifi_decrypt.py"
spec = importlib.util.spec_from_file_location("lf_wifi_decrypt", MODULE)
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)
PLAIN = b"\xaa\xaa\x03\x00\x00\x00\x08\x00synthetic payload"
MAC = b"\x08\x41" + b"\0" * 22
CIPHERTEXT = b"I" * 8 + b"C" * len(PLAIN) + b"M" * 8


def option(code, value, endian="<"):
    return struct.pack(endian + "HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def block(kind, body, endian="<"):
    body += b"\0" * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack(endian + "II", kind, length) + body + struct.pack(endian + "I", length)


def section(endian="<", linktype=105):
    return (block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
            + block(1, struct.pack(endian + "HHI", linktype, 0, 65535), endian))


def packet_block(packet, kind=6, endian="<", options=b"", interface=0):
    if kind == 3:
        prefix = struct.pack(endian + "I", len(packet))
    elif kind == 2:
        prefix = struct.pack(endian + "HHIIII", interface, 0, 17, 123456, len(packet), len(packet))
    else:
        prefix = struct.pack(endian + "IIIII", interface, 17, 123456, len(packet), len(packet))
    return block(kind, prefix + packet + b"\0" * (-len(packet) % 4) + options, endian)


def pcap(packets, endian="<", nano=False, wirelen=None):
    magic = (b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    result = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, 105)
    for packet in packets:
        result += struct.pack(endian + "IIII", 123, 987654123 if nano else 987654,
                              len(packet), wirelen or len(packet)) + packet
    return result


class CaptureTest(unittest.TestCase):
    def store(self, area, storage="memory", frame=1, packet=None, metadata=None):
        store = wd.MemoryFrameStore() if storage == "memory" else wd.SqliteFrameStore(Path(area) / "frames.sqlite")
        packet = packet if packet is not None else MAC + CIPHERTEXT
        metadata = metadata if metadata is not None else (0, 24, -1, -1, len(packet), PLAIN)
        with store.transaction():
            store.add_decoded(frame, False, 1, "wlan:llc:ip")
            store.add_capture(frame, metadata, 1)
        return store

    def write(self, area, data, store):
        source, destination = Path(area) / "input.pcap", Path(area) / "output.pcap"
        source.write_bytes(data)
        stats = wd.write_capture(source, destination, store, wd.file_sha256(source))
        return stats, destination.read_bytes()

    def test_all_classic_endianness_and_timestamp_resolutions(self):
        unchanged, protected = b"unmodified management packet", MAC + CIPHERTEXT
        for endian in ["<", ">"]:
            for nano in [False, True]:
                with self.subTest(endian=endian, nano=nano), tempfile.TemporaryDirectory() as area, \
                        closing(self.store(area, frame=2)) as store:
                    source = pcap([unchanged, protected], endian, nano)
                    stats, output = self.write(area, source, store)
                    expected = pcap([unchanged, b"\x08\x01" + MAC[2:] + PLAIN], endian, nano)
                    self.assertEqual(output, expected)
                    self.assertEqual(stats["frames_written"], 2)
                    self.assertEqual(stats["frames_decrypted"], 1)

    def test_pcapng_options_timestamps_and_unmodified_blocks(self):
        protected = MAC + CIPHERTEXT
        comment = option(1, b"keep this packet comment")
        old_hash = option(3, b"old ciphertext hash")
        custom = block(0xBAD, b"preserve unknown metadata")
        unchanged = packet_block(b"untouched management packet")
        source = section() + custom + unchanged + packet_block(protected, options=comment + old_hash + option(0, b""))
        with tempfile.TemporaryDirectory() as area, closing(self.store(area, frame=2)) as store:
            stats, output = self.write(area, source, store)
            expected = section() + custom + unchanged + packet_block(b"\x08\x01" + MAC[2:] + PLAIN, options=comment + option(0, b""))
            self.assertEqual(output, expected)
            self.assertEqual(stats["frames_written"], 2)

    def test_pcapng_packet_block_types_and_multiple_sections(self):
        for kind in [2, 3, 6]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as area, closing(self.store(area, frame=2)) as store:
                original = section("<") + packet_block(b"unchanged")
                original += section(">") + packet_block(MAC + CIPHERTEXT, kind=kind, endian=">")
                stats, output = self.write(area, original, store)
                expected = section("<") + packet_block(b"unchanged")
                expected += section(">") + packet_block(b"\x08\x01" + MAC[2:] + PLAIN, kind=kind, endian=">")
                self.assertEqual(output, expected)
                self.assertEqual(stats["frames_decrypted"], 1)

    def test_radiotap_flags_and_fcs_with_driver_padding(self):
        for padded in [False, True]:
            with self.subTest(padded=padded):
                mac = (b"\x88\x41" + MAC[2:] + b"\0\0") if padded else MAC
                padding = b"\xa5\xa5" if padded else b""
                flags = 0x54 | (0x20 if padded else 0)
                radio = struct.pack("<BBHI", 0, 0, 9, 2) + bytes([flags])
                packet = radio + mac + padding + CIPHERTEXT + b"FCS!"
                metadata = (9, 9 + len(mac) + len(padding), 8, len(packet) - 4, len(packet), PLAIN)
                output, reason = wd.rebuild_wlan_frame(packet, 127, metadata)
                self.assertIsNone(reason)
                plain_mac = mac[:1] + bytes([mac[1] & ~64]) + mac[2:]
                expected = radio[:8] + bytes([flags & ~0x44]) + plain_mac + padding + PLAIN
                expected += struct.pack("<I", zlib.crc32(plain_mac + PLAIN) & 0xffffffff)
                self.assertEqual(output, expected)

    def test_distinct_pcapng_interfaces_keep_their_ids_and_headers(self):
        interface = block(1, struct.pack("<HHI", 105, 0, 65535))
        prefix = section(linktype=1) + interface + packet_block(b"unchanged Ethernet packet", interface=0)
        original = prefix + packet_block(MAC + CIPHERTEXT, interface=1)
        with tempfile.TemporaryDirectory() as area, closing(self.store(area, frame=2)) as store:
            stats, output = self.write(area, original, store)
            self.assertEqual(output, prefix + packet_block(b"\x08\x01" + MAC[2:] + PLAIN, interface=1))
            self.assertEqual(stats["frames_written"], 2)

    def test_unknown_frames_fragments_and_truncation_remain_unchanged(self):
        cases = [(MAC[:1] + bytes([MAC[1] | 4]) + MAC[2:] + CIPHERTEXT, None, "fragmented data"),
                 (MAC[:22] + b"\x01\0" + CIPHERTEXT, None, "fragmented data"),
                 (MAC + CIPHERTEXT, len(MAC + CIPHERTEXT) + 1, "truncated packet")]
        for packet, wirelen, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as area, \
                    closing(self.store(area, packet=packet)) as store:
                original = pcap([packet], wirelen=wirelen)
                stats, output = self.write(area, original, store)
                self.assertEqual(original, output)
                self.assertEqual(stats["frames_decrypted"], 0)
                self.assertEqual(stats["skipped"], {reason: 1})
        with tempfile.TemporaryDirectory() as area, closing(wd.MemoryFrameStore()) as store:
            original = pcap([MAC + CIPHERTEXT])
            stats, output = self.write(area, original, store)
            self.assertEqual(original, output)
            self.assertEqual(stats["frames_decrypted"], 0)

    def test_invalid_capture_or_metadata_preserves_existing_output(self):
        for data in [b"invalid capture bytes", section()[:-1], section() + packet_block(MAC + CIPHERTEXT)[:-4] + b"bad!"]:
            with self.subTest(data=data[:12]), tempfile.TemporaryDirectory() as area, closing(self.store(area)) as store:
                source, destination = Path(area) / "input", Path(area) / "output"
                source.write_bytes(data)
                destination.write_bytes(b"previous complete output")
                with self.assertRaises(ValueError):
                    wd.write_capture(source, destination, store, wd.file_sha256(source))
                self.assertEqual(destination.read_bytes(), b"previous complete output")
                self.assertFalse(list(Path(area).glob(".lf_wifi_decrypt_*")))

    def test_interrupt_or_changed_input_keeps_old_output(self):
        for interrupted in [True, False]:
            with self.subTest(interrupted=interrupted), tempfile.TemporaryDirectory() as area, closing(self.store(area)) as store:
                source, destination = Path(area) / "input", Path(area) / "output"
                source.write_bytes(pcap([MAC + CIPHERTEXT]))
                destination.write_bytes(b"previous complete output")
                if interrupted:
                    with patch.object(wd, "rewrite_pcap", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                        wd.write_capture(source, destination, store, wd.file_sha256(source))
                else:
                    with self.assertRaisesRegex(RuntimeError, "Capture changed"):
                        wd.write_capture(source, destination, store, "wrong input hash")
                self.assertEqual(destination.read_bytes(), b"previous complete output")
                self.assertFalse(list(Path(area).glob(".lf_wifi_decrypt_*")))

    def test_capture_records_follow_first_successful_batch(self):
        for storage in ["sqlite", "memory"]:
            with self.subTest(storage=storage), tempfile.TemporaryDirectory() as area, closing(self.store(area, storage)) as store:
                metadata = (0, 24, -1, -1, 42, b"wrong payload")
                with store.transaction():
                    store.add_capture(1, metadata, 2)
                    store.add_decoded(2, True, 0, "wlan:llc")
                    store.add_capture(2, metadata, 0)
                rows = list(store.iter_capture())
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][1][-1], PLAIN)

    def test_lua_protocol_requires_complete_output(self):
        for contents in ["not a Lua export\n", "LF_WIFI_PLAINTEXT_V1\n", "LF_WIFI_PLAINTEXT_V1\nERROR\tfailed\nEND\n"]:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as area, closing(wd.MemoryFrameStore()) as store:
                def fake_run(command, env, timeout, secrets, output, _contents=contents):
                    output.write(_contents)
                with patch.object(wd, "run_checked", side_effect=fake_run), self.assertRaises(RuntimeError):
                    wd.collect_plaintext("tshark", Path("input"), Path(area), {}, 10, store, 0, [])

    def test_unicast_management_body_and_fcs_are_rewritten(self):
        # Deauthentication and action frames use a management body, not LLC.
        for subtype, body in [(0xC0, b"\x03\0"), (0xD0, b"\x08\0\x01\x02")]:
            for storage in ["memory", "sqlite"]:
                with self.subTest(subtype=subtype, storage=storage), tempfile.TemporaryDirectory() as area:
                    radio = struct.pack("<BBHI", 0, 0, 9, 2) + b"\x54"
                    mac = bytes([subtype, 0x40]) + b"\0" * 22
                    packet = radio + mac + b"I" * 8 + b"C" * len(body) + b"M" * 8 + b"FCS!"
                    metadata = (9, 33, 8, len(packet) - 4, len(packet), body)
                    store = wd.MemoryFrameStore() if storage == "memory" else wd.SqliteFrameStore(Path(area) / "frames.sqlite")
                    with closing(store), store.transaction():
                        store.add_capture(1, metadata, 1)
                        store.add_capture(1, (*metadata[:-1], b"wrong batch"), 2)
                        self.assertEqual(list(store.iter_capture()), [(1, metadata)])
                    plain, reason = wd.rebuild_wlan_frame(packet, 127, metadata)
                    self.assertIsNone(reason)
                    expected_mac = bytes([subtype, 0]) + mac[2:]
                    expected = radio[:8] + b"\x10" + expected_mac + body
                    expected += struct.pack("<I", zlib.crc32(expected_mac + body) & 0xffffffff)
                    self.assertEqual(plain, expected)
                    # Group BIP is authenticated plaintext; never rewrite it as
                    # a CCMP management frame, even if handed bogus metadata.
                    group = packet[:13] + b"\x01" + packet[14:]
                    self.assertEqual(wd.rebuild_wlan_frame(group, 127, metadata),
                                     (None, "unsupported management header"))

    def test_management_only_key_batch_after_all_data_is_decoded(self):
        for storage in ["sqlite", "memory"]:
            for management_only in [False, True]:
                with self.subTest(storage=storage, management_only=management_only), tempfile.TemporaryDirectory() as area:
                    data = MAC + CIPHERTEXT
                    mgmt = b"\xc0\x40" + b"\0" * 22 + b"I" * 8 + b"CC" + b"M" * 8
                    source, destination = Path(area) / "in.pcap", Path(area) / "out.pcap"
                    source.write_bytes(pcap([mgmt] if management_only else [data, mgmt]))
                    management_number = 1 if management_only else 2

                    def fake_run(command, env, timeout, secrets, output,
                                 _only=management_only, _data=data, _mgmt=mgmt, _number=management_number):
                        profile = Path(env["WIRESHARK_CONFIG_DIR"]).name
                        if "-X" in command:
                            output.write("LF_WIFI_PLAINTEXT_V1\n")
                            if profile == "batch_0" and not _only:
                                output.write(f"1\t0\t24\t-1\t-1\t{len(_data)}\t{PLAIN.hex()}\n")
                            if profile == "batch_1":
                                output.write(f"{_number}\t0\t24\t-1\t-1\t{len(_mgmt)}\t0300\n")
                            output.write("END\n")
                        else:
                            if not _only:
                                chain = "wlan:llc:ip" if profile == "batch_0" else "wlan:data"
                                output.write(f"1\t{chain}\t1\t2\t02:00:00:00:00:01\n")
                            output.write(f"{_number}\twlan\t1\t0\t02:00:00:00:00:01\n")
                    with patch.object(wd, "run_checked", side_effect=fake_run):
                        report = wd.decrypt_capture(source, temporal_keys=["ab" * 16, "cd" * 16], storage=storage,
                                                    key_batch_size=1, decrypted_pcap=destination)
                    self.assertTrue(report["verified"])
                    self.assertEqual(report["batches_tried"], 2)
                    capture = report["decrypted_capture"]
                    self.assertEqual(capture["management_frames_decrypted"], 1)
                    self.assertEqual(capture["data_frames_decrypted"], 0 if management_only else 1)
                    self.assertEqual(capture["frames_left_protected"], 0)
                    expected_mgmt = b"\xc0\0" + mgmt[2:24] + b"\x03\0"
                    expected_data = b"\x08\x01" + MAC[2:] + PLAIN
                    self.assertEqual(destination.read_bytes(), pcap([expected_mgmt] if management_only else [expected_data, expected_mgmt]))

    def test_capture_api_and_memory_mode_without_sqlite_or_packet_spool(self):
        for storage in ["sqlite", "memory"]:
            with self.subTest(storage=storage), tempfile.TemporaryDirectory() as area:
                source, destination = Path(area) / "input.pcap", Path(area) / "plain.pcap"
                original = MAC + CIPHERTEXT
                source.write_bytes(pcap([original]))

                def fake_run(command, env, timeout, secrets, output, _original=original):
                    if "-X" in command:
                        output.write(f"LF_WIFI_PLAINTEXT_V1\n1\t0\t24\t-1\t-1\t{len(_original)}\t{PLAIN.hex()}\nEND\n")
                    else:
                        chain = "wlan:data" if Path(env["WIRESHARK_CONFIG_DIR"]).name == "baseline" else "wlan:llc:ip"
                        output.write(f"1\t{chain}\t1\t2\t02:00:00:00:00:01\n")
                with patch.object(wd, "run_checked", side_effect=fake_run):
                    if storage == "memory":
                        with patch.object(wd.sqlite3, "connect", side_effect=AssertionError("SQLite used")), \
                                patch.object(wd.tempfile, "TemporaryFile", side_effect=AssertionError("Disk packet spool used")):
                            report = wd.decrypt_capture(source, temporal_keys=["ab" * 16], storage=storage, decrypted_pcap=destination)
                    else:
                        report = wd.decrypt_capture(source, temporal_keys=["ab" * 16], storage=storage, decrypted_pcap=destination)
                self.assertEqual(report["decrypted_capture"]["frames_written"], 1)
                self.assertEqual(report["decrypted_capture"]["frames_decrypted"], 1)
                self.assertEqual(report["decrypted_capture"]["frames_left_protected"], 0)
                self.assertEqual(destination.read_bytes(), pcap([b"\x08\x01" + MAC[2:] + PLAIN]))

    def test_capture_destination_cannot_replace_an_input(self):
        parsed = wd.parse_args(["--pcap", "input", "--decrypted-pcap", "output.pcapng"])
        self.assertEqual(parsed.report, Path("output.pcapng.json"))
        with tempfile.TemporaryDirectory() as area:
            source = Path(area) / "capture"
            source.write_bytes(pcap([MAC + CIPHERTEXT]))
            with self.assertRaises(ValueError):
                wd.decrypt_capture(source, temporal_keys=["ab" * 16], decrypted_pcap=source)
        with patch.object(wd.sys, "stderr"), self.assertRaises(SystemExit):
            wd.parse_args(["--purge_sqlite", "--decrypted-pcap", "output.pcapng"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--help_summary"]:
        print("Check decrypted capture output, metadata preservation and atomic writes using synthetic packets.")
    else:
        unittest.main()
