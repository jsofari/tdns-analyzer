#!/usr/bin/env python3
import argparse
import glob
import os
import re
import sys
import time
from datetime import datetime
from collections import deque, defaultdict
from typing import Dict, Deque, Tuple, Optional, List

# Technitium bracketed format:
# [2025-09-18 13:32:44 Local] [xxx.xxx.xxx.xxx:38232] [UDP] QNAME: ...; RCODE: NoError; ...
TS_BRACKET_REGEX = re.compile(r'^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<tz>[A-Za-z]+)\]')
CLIENT_BRACKET_REGEX = re.compile(r'\[(?P<addr>[0-9a-fA-F:\.]+):\d+\]')
RCODE_REGEX = re.compile(r'RCODE:\s*([A-Za-z0-9]+)')

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def pick_latest_file(logdir: str, pattern: str) -> Optional[str]:
    paths = glob.glob(os.path.join(logdir, pattern))
    if not paths:
        return None
    paths.sort(key=lambda p: os.path.getmtime(p))
    return paths[-1]

class FileFollower:
    def __init__(self, path: str, from_beginning: bool=False):
        self.path = path
        self.fd = None
        self.inode = None
        self.pos = 0
        self.from_beginning = from_beginning
        self._open()

    def _open(self):
        self.close()
        self.fd = open(self.path, 'r', encoding='utf-8', errors='replace')
        st = os.fstat(self.fd.fileno())
        self.inode = st.st_ino
        if self.from_beginning:
            self.pos = 0
            self.fd.seek(0, os.SEEK_SET)
        else:
            self.fd.seek(0, os.SEEK_END)
            self.pos = self.fd.tell()

    def maybe_rotate(self, new_path: str):
        if new_path != self.path:
            self.path = new_path
            self.from_beginning = True
            self._open()
            return
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            time.sleep(0.2)
            self._open()
            return
        if self.fd and self.inode is not None:
            try:
                cur = os.fstat(self.fd.fileno())
            except Exception:
                self._open(); return
            if cur.st_ino != self.inode or st.st_size < self.pos:
                self.from_beginning = True
                self._open()

    def read_new_lines(self) -> List[str]:
        if not self.fd:
            return []
        self.fd.seek(self.pos, os.SEEK_SET)
        lines = self.fd.readlines()
        self.pos = self.fd.tell()
        return lines

    def close(self):
        if self.fd:
            try:
                self.fd.close()
            except Exception:
                pass
        self.fd = None
        self.inode = None

def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

def human(n: float) -> str:
    return f"{n:,.0f}"

def render_table(title: str, rows: List[Tuple[str, float, float, int, float, float, str]], width: int=140, show: int=20):
    clear_screen()
    print(title)
    print("-" * min(width, 180))
    print(f"{'Rank':>4}  {'Client IP':<40} {'QPS(60s)':>10}  {'Peak(1s)':>10}  {'Count(60s)':>12}  {'NxDom%':>8}  {'Ref%':>6}  Flags")
    print("-" * min(width, 180))
    for i, (ip, qps, peak, cnt, nxd_pct, ref_pct, flags) in enumerate(rows[:show], 1):
        print(f"{i:>4}  {ip:<40} {qps:>10.1f}  {peak:>10.0f}  {human(cnt):>12}  {nxd_pct:>8.1f}  {ref_pct:>6.1f}  {flags}")
    if not rows:
        print("(no data yet)")
    print("-" * min(width, 180))
    sys.stdout.flush()

def main():
    ap = argparse.ArgumentParser(description="Fastnetmon-style live QPS monitor for Technitium DNS logs (with alerts)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--logfile", help="Path to a single log file")
    src.add_argument("--logdir", help="Directory containing rotating daily logs")
    ap.add_argument("--pattern", default="*.log", help="Glob pattern for logs in --logdir")
    ap.add_argument("--interval", type=float, default=2.0, help="Refresh interval seconds")
    ap.add_argument("--window", type=int, default=60, help="Sliding window seconds for QPS")
    ap.add_argument("--rows", type=int, default=20, help="Show top-N rows")
    ap.add_argument("--from-beginning", action="store_true", help="On first open, read from start of file")
    ap.add_argument("--debug", action="store_true", help="Debug to stderr")
    # Alerts
    ap.add_argument("--alert-qps", type=float, default=None, help="Alert when QPS(60s) exceeds this value")
    ap.add_argument("--alert-nxdomain", type=float, default=None, help="Alert when NxDomain%% exceeds this value")
    ap.add_argument("--alert-refused", type=float, default=None, help="Alert when Refused%% exceeds this value")
    ap.add_argument("--alert-cooldown", type=int, default=30, help="Seconds between repeated alerts per (ip,metric)")
    args = ap.parse_args()

    # State per IP
    from datetime import datetime
    ip_events: Dict[str, Deque[float]] = defaultdict(deque)              # timestamps
    ip_secs: Dict[str, Deque[Tuple[int,int]]] = defaultdict(deque)       # (sec, count) for peak
    ip_rc_counts: Dict[str, Dict[str,int]] = defaultdict(lambda: defaultdict(int))  # rcode -> count
    ip_rc_events: Dict[str, Deque[Tuple[float,str]]] = defaultdict(deque)           # (t, rcode)
    last_alert: Dict[Tuple[str,str], float] = {}  # (ip, metric) -> last time

    # Choose file
    current_path: Optional[str] = None
    follower: Optional[FileFollower] = None
    last_scan = 0.0

    if args.logfile:
        current_path = args.logfile
        follower = FileFollower(current_path, from_beginning=args.from_beginning)
    else:
        latest = pick_latest_file(args.logdir, args.pattern)
        if not latest:
            print(f"No files found in {args.logdir} matching {args.pattern}", file=sys.stderr)
            sys.exit(1)
        current_path = latest
        follower = FileFollower(current_path, from_beginning=args.from_beginning)

    while True:
        now = time.time()

        # rotation
        if args.logdir and (now - last_scan) >= max(1.0, args.interval):
            last_scan = now
            latest = pick_latest_file(args.logdir, args.pattern)
            if latest and latest != current_path:
                if args.debug:
                    print(f"[DEBUG] Switch logfile: {current_path} -> {latest}", file=sys.stderr)
                current_path = latest
                follower.maybe_rotate(latest)

        # read new lines
        lines = follower.read_new_lines()
        for line in lines:
            if "QNAME:" not in line:
                continue
            m_ts = TS_BRACKET_REGEX.search(line)
            if not m_ts:
                if args.debug: sys.stderr.write(f"[DEBUG] No TS match: {line.strip()}\n")
                continue
            ts = parse_timestamp(m_ts.group("ts"))
            if not ts:
                if args.debug: sys.stderr.write(f"[DEBUG] TS parse failed: {m_ts.group('ts')}\n")
                continue
            m_cli = CLIENT_BRACKET_REGEX.search(line)
            if not m_cli:
                if args.debug: sys.stderr.write(f"[DEBUG] No client match: {line.strip()}\n")
                continue
            ip = m_cli.group("addr")
            m_rc = RCODE_REGEX.search(line)
            rcode = m_rc.group(1) if m_rc else "Unknown"

            t = ts.timestamp()

            # events
            ip_events[ip].append(t)

            # per-second bucket
            sec = int(t)
            sd = ip_secs[ip]
            if sd and sd[-1][0] == sec:
                sd[-1] = (sec, sd[-1][1] + 1)
            else:
                sd.append((sec, 1))

            # rcode
            ip_rc_counts[ip][rcode] += 1
            ip_rc_events[ip].append((t, rcode))

        # prune
        cutoff = time.time() - args.window
        for ip in list(ip_events.keys()):
            dq = ip_events[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del ip_events[ip]

        for ip in list(ip_secs.keys()):
            sd = ip_secs[ip]
            while sd and sd[0][0] < int(cutoff):
                sd.popleft()
            if not sd:
                del ip_secs[ip]

        for ip in list(ip_rc_events.keys()):
            rqd = ip_rc_events[ip]
            rcmap = ip_rc_counts[ip]
            while rqd and rqd[0][0] < cutoff:
                _, rc = rqd.popleft()
                rcmap[rc] -= 1
                if rcmap[rc] <= 0:
                    del rcmap[rc]
            if not rqd:
                del ip_rc_events[ip]
                if ip in ip_rc_counts and not ip_rc_counts[ip]:
                    del ip_rc_counts[ip]

        # compute rows + gather alerts
        alerts: List[str] = []
        rows = []
        for ip, dq in ip_events.items():
            cnt = len(dq)
            qps = cnt / float(args.window) if args.window > 0 else 0.0
            sd = ip_secs.get(ip, deque())
            peak = max((c for _, c in sd), default=0)
            rcmap = ip_rc_counts.get(ip, {})
            nxd = rcmap.get("NxDomain", 0) + rcmap.get("NXDOMAIN", 0)
            ref = rcmap.get("Refused", 0) + rcmap.get("REFUSED", 0)
            nxd_pct = (100.0 * nxd / cnt) if cnt else 0.0
            ref_pct = (100.0 * ref / cnt) if cnt else 0.0

            # flags / alerting
            flags_list = []
            now_t = time.time()
            if args.alert_qps is not None and qps > args.alert_qps:
                flags_list.append("QPS")
                key = (ip, "QPS")
                if (key not in last_alert) or (now_t - last_alert[key] >= args.alert_cooldown):
                    alerts.append(f"[ALERT] High QPS: {ip} {qps:.1f} qps (>{args.alert_qps})")
                    last_alert[key] = now_t
            if args.alert_nxdomain is not None and nxd_pct > args.alert_nxdomain:
                flags_list.append("NXD")
                key = (ip, "NXD")
                if (key not in last_alert) or (now_t - last_alert[key] >= args.alert_cooldown):
                    alerts.append(f"[ALERT] High NxDomain%: {ip} {nxd_pct:.1f}% (>{args.alert_nxdomain}%)")
                    last_alert[key] = now_t
            if args.alert_refused is not None and ref_pct > args.alert_refused:
                flags_list.append("REF")
                key = (ip, "REF")
                if (key not in last_alert) or (now_t - last_alert[key] >= args.alert_cooldown):
                    alerts.append(f"[ALERT] High Refused%: {ip} {ref_pct:.1f}% (>{args.alert_refused}%)")
                    last_alert[key] = now_t

            flags = "[" + ",".join(flags_list) + "]" if flags_list else ""
            rows.append((ip, qps, float(peak), cnt, nxd_pct, ref_pct, flags))

        rows.sort(key=lambda r: (r[1], r[2], r[3]), reverse=True)

        title = f"Technitium DNS Live QPS (window {args.window}s, interval {args.interval}s)   file={current_path}   time={datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        clear_screen()
        # Render table
        print(title)
        print("-" * 180)
        print(f"{'Rank':>4}  {'Client IP':<40} {'QPS(60s)':>10}  {'Peak(1s)':>10}  {'Count(60s)':>12}  {'NxDom%':>8}  {'Ref%':>6}  Flags")
        print("-" * 180)
        for i, (ip, qps, peak, cnt, nxd_pct, ref_pct, flags) in enumerate(rows[:args.rows], 1):
            print(f"{i:>4}  {ip:<40} {qps:>10.1f}  {peak:>10.0f}  {human(cnt):>12}  {nxd_pct:>8.1f}  {ref_pct:>6.1f}  {flags}")
        if not rows:
            print("(no data yet)")
        print("-" * 180)

        # Alerts block
        if alerts:
            print("ALERTS:")
            for a in alerts:
                print(a)
            print("-" * 180)

        sys.stdout.flush()
        time.sleep(args.interval)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
