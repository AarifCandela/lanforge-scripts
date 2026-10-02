#!/usr/bin/env python3
"""
lf_fg_pcap.py -- LANforge toolbox script for pcap/frame playback over
Layer-3 custom_ether endpoints on monitor ports (Frame Generator path).

Follows the toolbox conventions of py-scripts/test_l3.py: discrete
single-purpose actions, executes and exits, non-zero exit on failure.
Intended for users and AI logic to compose into workflows.

Examples:
  # Create a monitor on the mt7996 radio and bind the channel
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --create_monitor \
      --radio wiphy3 --monitor_name fgmon0 --channel 36

  # Build a playback CX from an existing pcap (creates endps + cx,
  # attaches the pcap, leaves it STOPPED)
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --build_pcap_cx \
      --port fgmon0 --pcap_file /tmp/replay.pcap --cx_name fgcx0

  # Or build frames from a preset instead of a pcap file
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --build_pcap_cx \
      --port fgmon0 --frame rts --count 20 --cx_name fgcx0 \
      --ra 00:11:22:33:44:55 --ta 00:0a:52:0c:ef:0f

  # Start / stop / delete (same semantics as test_l3 toolbox)
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --start_cx fgcx0
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --stop_cx fgcx0
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --del_cx fgcx0

  # Query state
  python3 lf_fg_pcap.py --lfmgr 192.168.204.24 --cx_status fgcx0

Notes from OTA validation on 5.5.3 (LAN-5243):
  - pcap playback is the working TX path on monitor ports; payload-only
    mode (set_endp_payload) spins on sendto EINVAL on monitors
  - add_cx must run BEFORE set_endp_file or CX creation is refused
  - a freshly created monitor stays admin-down and set_port admin-up
    returns -22; bring the link up and bind the channel from the host
    (this script does both when run on the LANforge host)
"""

import argparse
import json
import logging
import os
import struct
import subprocess
import sys
import tempfile
import time

import requests

logger = logging.getLogger(os.path.basename(__file__))

DEFAULT_MGR_PORT = 8080


# ---------------------------------------------------------------------------
# Manager JSON API client
# ---------------------------------------------------------------------------

class LFJson:
    def __init__(self, host, port=DEFAULT_MGR_PORT, timeout=20):
        self.base = "http://%s:%s" % (host, port)
        self.timeout = timeout

    def post(self, cmd, payload):
        r = requests.post(self.base + "/cli-json/" + cmd, json=payload,
                          timeout=self.timeout)
        try:
            d = r.json()
        except ValueError:
            raise RuntimeError("%s: non-JSON reply: %s" % (cmd, r.text[:200]))
        body = d.get("LAST", d)
        rv = body.get("response", None)
        if d.get("status") == "BAD_REQUEST" or (rv is not None and str(rv).strip() not in ("0", "")):
            raise RuntimeError("%s failed: %s" % (cmd, json.dumps(d)[:300]))
        return d

    def get(self, uri):
        r = requests.get(self.base + uri, timeout=self.timeout)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Frame builder (presets) -- same shapes as the webgui FG integration,
# OTA-validated on mt7996 monitors
# ---------------------------------------------------------------------------

_BROADCAST = "ff:ff:ff:ff:ff:ff"

_FRAME_TYPES = {
    "rts": (1, 11), "cts": (1, 12), "ack": (1, 13),
    "block-ack-request": (1, 8), "block-ack": (1, 9),
}


def _mac(s):
    if s is None or str(s).strip().lower() in ("", "none", "default", "na"):
        s = _BROADCAST
    s = str(s).replace("-", ":").replace(".", ":").lower()
    if len(s) == 12:
        s = ":".join(s[i:i + 2] for i in range(0, 12, 2))
    b = bytes(int(x, 16) for x in s.split(":"))
    if len(b) != 6:
        raise ValueError("bad MAC: %r" % s)
    return b


def _seq_bytes(seq):
    frag = seq & 0xF
    n = (seq >> 4) & 0xFFF
    return bytes([(n & 0xF) << 4 | frag, (n >> 4) & 0xFF])


def build_frame(kind, spec):
    kind = (kind or "").lower()
    if kind in _FRAME_TYPES:
        ftype, fsub = _FRAME_TYPES[kind]
        fc = (fsub << 4) | (ftype << 2)
        dur = int(spec.get("duration", 0)) & 0xFFFF
        ra = _mac(spec.get("ra", _BROADCAST))
        if kind in ("rts", "block-ack-request", "block-ack"):
            ta = _mac(spec.get("ta", spec.get("src", _BROADCAST)))
            return struct.pack("<HH", fc, dur) + ra + ta
        return struct.pack("<HH", fc, dur) + ra
    if kind == "deauth":
        fc = 0xC000
    elif kind == "disassociate":
        fc = 0xA000
    elif kind == "probe-request":
        fc = 0x0040
    elif kind == "beacon":
        fc = 0x0080
    elif kind == "custom":
        hx = "".join((spec.get("hex") or "").split())
        if not hx:
            raise ValueError("custom frame requires --hex")
        return bytes.fromhex(hx)
    else:
        raise ValueError("unsupported frame type: %r" % kind)

    dur = int(spec.get("duration", 0)) & 0xFFFF
    da = _mac(spec.get("da", spec.get("ra", _BROADCAST)))
    sa = _mac(spec.get("sa", spec.get("ta", _BROADCAST)))
    bssid = _mac(spec.get("bssid", _BROADCAST))
    frag_seq = _seq_bytes(int(spec.get("seq", 0)))
    if kind == "probe-request":
        ssid = str(spec.get("ssid", ""))
        ssid_ie = bytes([0x00, len(ssid)]) + ssid.encode() if ssid else b""
        rates = bytes([0x01, 8, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
        return struct.pack("<HH", fc, dur) + da + sa + bssid + frag_seq + ssid_ie + rates
    if kind == "beacon":
        tsf = struct.pack("<Q", int(spec.get("tsf", 0)))
        bi = struct.pack("<H", int(spec.get("beacon_interval", 100)))
        caps = struct.pack("<H", int(spec.get("capabilities", 0x0411)))
        ssid = str(spec.get("ssid", "FG"))
        body = tsf + bi + caps
        body += bytes([0x00, len(ssid)]) + ssid.encode()
        body += bytes([0x01, 8, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
        body += bytes([0x03, 1, int(spec.get("ds_channel", 6))])
        return struct.pack("<HH", fc, dur) + da + sa + bssid + frag_seq + body
    reason = struct.pack("<H", int(spec.get("reason", 7 if kind == "deauth" else 8)) & 0xFFFF)
    return struct.pack("<HH", fc, dur) + da + sa + bssid + frag_seq + reason


def radiotap_header(rate_mbps=24.0, mcs_index=None, width_mhz=20):
    """OTA-proven inject shape: FLAGS|TX_FLAGS(|RATE or |MCS), no channel
    field, no-ACK. (Radiotap headers carrying a CHANNEL field failed to
    radiate on mt76 monitors during validation; this exact shape was
    OTA-verified 20/20.)"""
    present = (1 << 1) | (1 << 15)  # FLAGS | TX_FLAGS
    if mcs_index is not None:
        present |= 1 << 29  # MCS
        # mcs field: known(3) flags(1) mcs(1)
        known = {20: 0x00, 40: 0x01, 80: 0x04, 160: 0x08}.get(width_mhz, 0x00)
        body = struct.pack("<BBBB", 0x03, 0x00, known, mcs_index & 0xFF)
    else:
        present |= 1 << 2  # RATE (500 kbps units)
        rate_u = max(1, int(round(rate_mbps * 2)))
        if rate_u > 255:
            raise ValueError("legacy rate must be <= 127.5 Mbps")
        body = struct.pack("<BBH", 0x00, rate_u, 0x0008)  # flags, rate, TX-flags: no-ACK
    hdr_len = 8 + len(body)
    return struct.pack("<BBHI", 0, 0, hdr_len, present) + body


def make_pcap(frames, rtap=None, gap_ms=100):
    rtap = rtap or radiotap_header()
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    t = int(time.time())
    for i, fr in enumerate(frames):
        pkt = rtap + fr
        out += struct.pack("<IIII", t, i * gap_ms * 1000, len(pkt), len(pkt)) + pkt
    return out


# ---------------------------------------------------------------------------
# Toolbox actions
# ---------------------------------------------------------------------------

def _wait_port(lf, name, tries=12, delay=2):
    for _ in range(tries):
        try:
            ports = lf.get("/port/1/1/list").get("interfaces", [])
            for row in ports:
                for _k, v in row.items():
                    if str(v.get("alias", "")) == name:
                        return True
        except Exception:
            pass
        time.sleep(delay)
    return False


def action_create_monitor(lf, args):
    lf.post("add_monitor", {
        "shelf": args.shelf, "resource": args.resource,
        "radio": args.radio, "ap_name": args.monitor_name,
    })
    if not _wait_port(lf, args.monitor_name):
        raise RuntimeError("monitor %s did not appear in port table" % args.monitor_name)
    # 5.5.3: new monitors stay admin-down; set_port admin-up returns -22.
    # Bring the link up + bind the channel host-side (works when this script
    # runs on the LANforge host, which is the normal toolbox case).
    if args.channel:
        subprocess.run(["iw", "dev", args.monitor_name, "set", "channel",
                        str(args.channel), "HT20"], check=False, capture_output=True)
    subprocess.run(["ip", "link", "set", args.monitor_name, "up"],
                   check=False, capture_output=True)
    print("monitor-ready %s" % args.monitor_name)
    return True


def action_build_pcap_cx(lf, args):
    if not args.port:
        raise RuntimeError("--build_pcap_cx requires --port")
    if bool(args.pcap_file) == bool(args.frame):
        raise RuntimeError("specify exactly one of --pcap_file or --frame")

    if args.frame:
        spec = {
            "ra": args.ra, "ta": args.ta, "da": args.da, "sa": args.sa,
            "bssid": args.bssid, "ssid": args.ssid, "hex": args.hex,
            "reason": args.reason, "duration": args.duration,
        }
        n = max(1, args.count or 1)
        seq0 = 0
        frames = []
        for i in range(n):
            s = dict(spec)
            s["seq"] = seq0 + i * 16
            s["tsf"] = i * 102400
            frames.append(build_frame(args.frame, s))
        pcap_path = args.pcap_out or tempfile.mktemp(suffix=".pcap", prefix="fg-tb-")
        with open(pcap_path, "wb") as f:
            f.write(make_pcap(frames, gap_ms=args.gap_ms))
        logger.info("built pcap %s (%d %s frames)", pcap_path, n, args.frame)
    else:
        pcap_path = args.pcap_file
        if not os.path.exists(pcap_path):
            raise RuntimeError("pcap not found: %s" % pcap_path)

    cx = args.cx_name or "fgcx0"
    endp_a, endp_b = cx + "-tx", cx + "-rx"
    for e in (endp_a, endp_b):
        lf.post("add_endp", {"shelf": args.shelf, "resource": args.resource,
                             "port": args.port, "type": "custom_ether",
                             "alias": e})
    # ORDER MATTERS: add_cx before set_endp_file or CX creation is refused.
    lf.post("add_cx", {"alias": cx, "test_mgr": "default_tm",
                       "tx_endp": endp_a, "rx_endp": endp_b})
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if cx in lf.get("/cx"):
                break
        except Exception:
            pass
        time.sleep(1)
    lf.post("set_endp_file", {"name": endp_a, "playback": "ON",
                              "file": pcap_path})
    if args.rate:
        lf.post("set_endp_tx_bounds", {"name": endp_a,
                                       "min_tx_rate": args.rate,
                                       "max_tx_rate": args.rate,
                                       "is_bursty": "NO"})
    print("cx-built %s tx=%s pcap=%s" % (cx, endp_a, pcap_path))
    return True


def action_cx_state(lf, args, state):
    raw = getattr(args, "start_cx", None) or getattr(args, "stop_cx", None)
    names = _parse_list(args, raw)
    if raw is None:
        raise RuntimeError("no CX names given")
    if not names:
        names = [k for k in lf.get("/cx").keys()
                 if not k.startswith(("handler", "uri"))]
    for cx in names:
        lf.post("set_cx_state", {"test_mgr": "default_tm", "cx_name": cx,
                                 "cx_state": state})
        print("cx-%s %s" % (state.lower(), cx))
    return True


def action_del_cx(lf, args):
    raw = getattr(args, "del_cx", None)
    names = _parse_list(args, raw)
    if raw is None:
        raise RuntimeError("no CX names given")
    if not names:
        names = [k for k in lf.get("/cx").keys()
                 if not k.startswith(("handler", "uri"))]
    for cx in names:
        lf.post("rm_cx", {"test_mgr": "default_tm", "cx_name": cx})
        lf.post("rm_endp", {"endp_name": cx + "-tx"})
        lf.post("rm_endp", {"endp_name": cx + "-rx"})
        print("cx-deleted %s" % cx)
    return True


def action_cx_status(lf, args):
    names = _parse_list(args, getattr(args, "cx_status", None))
    cxs = lf.get("/cx")
    out = {}
    for cx in (names if names else cxs.keys()):
        if cx.startswith(("handler", "uri")):
            continue
        if names and cx not in names:
            continue
        info = cxs.get(cx, {})
        out[cx] = info
    print(json.dumps(out, indent=1, default=str))
    return True


def action_ports_admin(lf, args, up=True):
    raw = getattr(args, "ports_up", None) if up else getattr(args, "ports_down", None)
    names = _parse_list(args, raw)
    if not names:
        raise RuntimeError("no ports given")
    for p in names:
        lf.post("set_port", {"shelf": args.shelf, "resource": args.resource,
                             "port": p,
                             "current_flags": 0 if up else 1})
        print("port-%s %s" % ("up" if up else "down", p))
    return True


def _parse_list(args, raw=None):
    raw = raw if raw is not None else getattr(args, "start_cx", None)
    if raw is None:
        raw = getattr(args, "stop_cx", None)
    if raw is None:
        raw = getattr(args, "del_cx", None)
    if raw is None:
        raw = getattr(args, "cx_status", None)
    if raw is None:
        raw = getattr(args, "ports_up", None) or getattr(args, "ports_down", None)
    if not raw:
        return []
    if raw == "all":
        return []
    if isinstance(raw, str):
        return [x.strip() for x in raw.split(",") if x.strip()]
    return [str(x).strip() for x in raw]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description="LANforge toolbox: Layer-3 pcap/frame playback (Frame Generator path)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for usage examples.")
    req = p.add_argument_group("required")
    req.add_argument("--lfmgr", default="localhost", help="LANforge manager host (default localhost)")
    req.add_argument("--lfmgr_port", "--mgr_port", dest="lfmgr_port",
                     type=int, default=DEFAULT_MGR_PORT,
                     help="manager HTTP/JSON port (default %d)" % DEFAULT_MGR_PORT)
    req.add_argument("--shelf", type=int, default=1)
    req.add_argument("--resource", type=int, default=1)

    g = p.add_argument_group("toolbox actions")
    g.add_argument("--create_monitor", action="store_true",
                   help="Toolbox action: create monitor on --radio as --monitor_name")
    g.add_argument("--build_pcap_cx", action="store_true",
                   help="Toolbox action: build custom_ether CX on --port with pcap playback (--pcap_file or --frame preset)")
    g.add_argument("--start_cx", nargs="?", const="all", default=None,
                   help="Toolbox action: start CX (comma list)")
    g.add_argument("--stop_cx", nargs="?", const="all", default=None,
                   help="Toolbox action: stop CX (comma list)")
    g.add_argument("--del_cx", nargs="?", const="all", default=None,
                   help="Toolbox action: delete CX + endpoints (comma list)")
    g.add_argument("--cx_status", nargs="?", const="all", default=None,
                   help="Toolbox action: print CX state (comma list or all)")

    g.add_argument("--ports_up", nargs="+", default=None,
                   help="Toolbox action: ports admin up")
    g.add_argument("--ports_down", nargs="+", default=None,
                   help="Toolbox action: ports admin down")

    o = p.add_argument_group("action options")
    o.add_argument("--radio", default=None, help="radio for --create_monitor (e.g. wiphy3)")
    o.add_argument("--monitor_name", default=None, help="name for created monitor")
    o.add_argument("--channel", type=int, default=None,
                   help="channel to bind on the monitor (e.g. 36)")
    o.add_argument("--port", default=None, help="port for --build_pcap_cx")
    o.add_argument("--cx_name", default=None, help="CX name prefix for --build_pcap_cx (default fgcx0)")
    o.add_argument("--pcap_file", default=None, help="existing pcap to replay")
    o.add_argument("--frame", default=None,
                   help="preset frame to build: rts cts ack deauth disassociate probe-request beacon custom")
    o.add_argument("--count", type=int, default=1, help="number of preset frames (default 1)")
    o.add_argument("--gap_ms", type=int, default=100, help="inter-frame gap in pcap ms (default 100)")
    o.add_argument("--rate", type=int, default=None,
                   help="tx bounds pps for the playback (e.g. 100)")
    o.add_argument("--pcap_out", default=None,
                   help="where to write the generated pcap (default temp file)")
    o.add_argument("--ra", default=_BROADCAST)
    o.add_argument("--ta", default=None)
    o.add_argument("--da", default=None)
    o.add_argument("--sa", default=None)
    o.add_argument("--bssid", default=None)
    o.add_argument("--ssid", default="")
    o.add_argument("--hex", default=None, help="custom frame hex (with --frame custom)")
    o.add_argument("--reason", type=int, default=None)
    o.add_argument("--duration", type=int, default=0)

    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s %(message)s")

    actions = [
        ("create_monitor", lambda: action_create_monitor(lf, args)),
        ("build_pcap_cx", lambda: action_build_pcap_cx(lf, args)),
        ("start_cx", lambda: action_cx_state(lf, args, "RUNNING")),
        ("stop_cx", lambda: action_cx_state(lf, args, "STOPPED")),
        ("del_cx", lambda: action_del_cx(lf, args)),
        ("cx_status", lambda: action_cx_status(lf, args)),
        ("ports_up", lambda: action_ports_admin(lf, args, True)),
        ("ports_down", lambda: action_ports_admin(lf, args, False)),
    ]
    chosen = [(n, f) for n, f in actions if getattr(args, n) is not None
              and getattr(args, n) is not False]
    if not chosen:
        p.print_help()
        return 1

    lf = LFJson(args.lfmgr, args.lfmgr_port)
    ok = True
    for name, fn in chosen:
        try:
            logger.info("toolbox action: %s", name)
            fn()
        except Exception as e:  # noqa: BLE001
            logger.error("action %s failed: %s", name, e)
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
