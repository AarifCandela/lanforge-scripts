"""Check stable brief-text MAC labels with synthetic addresses and keys."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / "lf_wifi_decrypt.py"
spec = importlib.util.spec_from_file_location("decoder_anonymous", MODULE)
wd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wd)

PACKETS = ("1 02:00:00:00:00:01 -> 02:00:00:00:00:02 Info: SA=02:00:00:00:00:01\n"
           "2 02:00:00:00:00:02 -> ff:ff:ff:ff:ff:ff Info: 2001:db8::1\n"
           "3 ff:ff:ff:ff:ff:ff -> 02:00:00:00:00:01 Info: 192.0.2.1\n")
ANONYMOUS = ("1 A -> B Info: SA=A\n"
             "2 B -> C Info: 2001:db8::1\n"
             "3 C -> A Info: 192.0.2.1\n")


def packets(command, env, timeout, secrets, output):
    """Give frame 3 to batch zero and frame 1 to batch one, out of order."""
    profile = Path(env["WIRESHARK_CONFIG_DIR"]).name
    if "-T" in command:
        for number in (1, 2, 3):
            readable = number == 2 or (profile != "baseline" and (number == 3 or profile == "batch_1"))
            chain = "wlan:llc:ip" if readable else "wlan:data"
            output.write(f"{number}\t{chain}\t{int(number != 2)}\t2\t02:00:00:00:00:01\n")
    else:
        output.write(PACKETS)


class AnonymousTest(unittest.TestCase):
    def test_all_occurrences_and_equivalent_address_forms(self):
        mask = wd.MacAnonymizer()
        self.assertEqual(mask.replace("aa:bb:cc:dd:ee:ff AA-BB-CC-DD-EE-FF aa:bb:cc:dd:ee:ff"), "A A A")
        self.assertEqual(mask.replace("RA=ff:ff:ff:ff:ff:ff, SA=AA:BB:CC:DD:EE:FF"), "RA=B, SA=A")
        self.assertEqual(len(mask.labels), 2)

    def test_short_hex_ipv6_eui64_and_mixed_separators_unchanged(self):
        text = ("abc123 001122334455 192.0.2.1 2001:db8::1 ::aa:bb:cc:dd:ee:ff "
                "aa:bb:cc:dd:ee:ff:00:11 00-aa-bb-cc-dd-ee-ff-11 "
                "00:11:22:33:44:556 000:11:22:33:44:55 aa:bb-cc:dd:ee:ff")
        mask = wd.MacAnonymizer()
        self.assertEqual(mask.replace(text), text)
        self.assertEqual(mask.labels, {})

    def test_labels_continue_past_z_and_zz(self):
        mask = wd.MacAnonymizer()
        labels = [mask.replace(f"02:00:00:00:{index // 256:02x}:{index % 256:02x}") for index in range(704)]
        self.assertEqual([labels[index] for index in (0, 25, 26, 27, 51, 52, 701, 702, 703)],
                         ["A", "Z", "AA", "AB", "AZ", "BA", "ZZ", "AAA", "AAB"])
        self.assertEqual(len(set(labels)), 704)
        self.assertEqual(mask.replace("02:00:00:00:00:00"), "A")

    def test_capture_order_stdout_file_and_storage_match(self):
        for storage in ("memory", "sqlite"):
            for to_file in (False, True):
                with self.subTest(storage=storage, to_file=to_file), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source, output, report_path = root / "input.pcap", root / "output.txt", root / "report.json"
                    source.write_bytes(b"synthetic capture")
                    stream = io.StringIO()
                    with patch.object(wd, "run_checked", side_effect=packets):
                        report = wd.decrypt_capture(source, temporal_keys=["11" * 16, "22" * 16],
                                                    key_batch_size=1, storage=storage, anonymous=True,
                                                    output=output if to_file else None,
                                                    output_stream=None if to_file else stream, report_path=report_path)
                    text = output.read_text(encoding="utf-8") if to_file else stream.getvalue()
                    self.assertEqual(text, ANONYMOUS)
                    self.assertTrue(report["anonymous"])
                    self.assertEqual(report["anonymous_mac_count"], 3)
                    self.assertEqual(report["batches_tried"], 2)
                    self.assertEqual(report["newly_decoded_protected_frames"], 2)
                    self.assertEqual(report["text_frames_written"], 3)
                    saved_report = report_path.read_text(encoding="utf-8")
                    self.assertEqual(json.loads(saved_report), report)
                    self.assertNotRegex(saved_report, wd.MAC_ADDRESS)
                    self.assertEqual(source.read_bytes(), b"synthetic capture")
                    self.assertFalse(stream.closed)

    def test_disabled_output_and_mapping_reset_between_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.pcap"
            source.touch()
            for anonymous in (False, True, True):
                stream = io.StringIO()
                with patch.object(wd, "run_checked", side_effect=packets):
                    report = wd.decrypt_capture(source, temporal_keys=["11" * 16, "22" * 16], key_batch_size=1,
                                                output_stream=stream, storage="memory", anonymous=anonymous)
                self.assertEqual(stream.getvalue(), ANONYMOUS if anonymous else PACKETS)
                self.assertEqual(report["anonymous_mac_count"], 3 if anonymous else 0)

    def test_only_emitted_frames_assign_labels(self):
        with contextlib.closing(wd.MemoryFrameStore()) as store:
            # A filtered-out frame would have used a different address first.
            store.add_output(2085, "2085 ff:ff:ff:ff:ff:ff -> 02:00:00:00:00:02\n", 0)
            stream = io.StringIO()
            self.assertEqual(wd.write_text(store, None, stream, anonymous=True), 2)
            self.assertEqual(stream.getvalue(), "2085 A -> B\n")

    def test_cli_flag_reaches_api_and_defaults_off(self):
        self.assertFalse(wd.parse_args(["--pcap", "input"]).anonymous)
        self.assertTrue(wd.parse_args(["--pcap", "input", "--anonymous"]).anonymous)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.pcap"
            source.touch()
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(wd, "run_checked", side_effect=packets), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                status = wd.main(["--pcap", str(source), "--tk", "11" * 16, "--tk", "22" * 16,
                                  "--key-batch-size", "1", "--anonymous", "--no-sqlite", "--quiet"])
            self.assertEqual(status, 0)
            self.assertEqual(stdout.getvalue(), ANONYMOUS)

    def test_verbose_rejected_before_tshark(self):
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as error:
                wd.parse_args(["--pcap", "input", "--anonymous", "--mode", "verbose"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--anonymous requires --mode brief", stderr.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.pcap"
            source.touch()
            with patch.object(wd, "run_checked") as run:
                with self.assertRaisesRegex(ValueError, "Anonymous output requires brief mode"):
                    wd.decrypt_capture(source, anonymous=True, mode="verbose")
                run.assert_not_called()

    def test_interrupted_anonymous_write_preserves_previous_output(self):
        def interrupted():
            yield PACKETS
            raise KeyboardInterrupt

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output.txt"
            output.write_text("previous completed output\n", encoding="utf-8")
            with contextlib.closing(wd.MemoryFrameStore()) as store, patch.object(store, "iter_text", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    wd.write_text(store, output, None, anonymous=True)
            self.assertEqual(output.read_text(encoding="utf-8"), "previous completed output\n")
            self.assertEqual(list(Path(directory).iterdir()), [output])


if __name__ == "__main__":
    if sys.argv[1:] == ["--help_summary"]:
        print("Check per-output MAC labels, ordering, storage parity and brief-only validation.")
    else:
        unittest.main()
