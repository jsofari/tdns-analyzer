#!/usr/bin/env python3
import argparse
import glob
import os
import re
import sys
import time
from datetime import datetime
from typing import Dict, Tuple, Optional

# Format contoh:
# [2025-09-18 13:32:44 Local] [103.175.236.112:38232] [UDP] QNAME: ...
TS_BRACKET_REGEX = re.compile(r'^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<tz>[A-Za-z]+)\]')
CLIENT_BRACKET_REGEX = re.compile(r'\[(?P<addr>[0-9a-fA-F:\.]+):\d+\]')

def parse_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

def pick_latest_file(logdir: str, pattern: str, debug: bool=False) -> Optional[str]:
    paths = glob.glob(os.path.join(logdir, pattern))
    if not paths:
        if debug:
            print(f"[DEBUG] No files match {os.path.join(logdir, pattern)}", file=sys.stderr)
        return None
    paths.sort(key=lambda p: os.path.getmtime(p))
    if debug:
        print(f"[DEBUG] Candidates: {paths}", file=sys.stderr)
    return paths[-1]

def tail_file(path: str, poll_interval: float = 0.25, from_beginning: bool=False):
    while True:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                if not from_beginning:
                    f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if line:
                        yield line
                    else:
                        time.sleep(poll_interval)
        except FileNotFoundError:
            time.sleep(poll_interval)

def iter_file_once(path: str):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield line

def summarize_minute(minute_key: str, counter: Dict[str, int], top: int, csv_fh: Optional[object], heading="Minute"):
    if not counter:
        return
    pairs = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
    print(f"\n=== {heading} {minute_key} ===")
    width = max(15, max((len(ip) for ip, _ in pairs[:top]), default=15))
    print(f"{'Client IP'.ljust(width)}  QPM")
    print(f"{'-'*width}  ----")
    for ip, cnt in pairs[:top]:
        print(f"{ip.ljust(width)}  {cnt}")
    total = sum(counter.values())
    unique = len(counter)
    print(f"Total queries: {total} | Unique clients: {unique}")
    sys.stdout.flush()

    if csv_fh is not None:
        for ip, cnt in pairs:
            csv_fh.write(f"{minute_key},{ip},{cnt}\n")
        csv_fh.flush()

def process_line(line: str, args, state: dict, csv_fh: Optional[object]):
    if "QNAME:" not in line:
        return False

    m_ts = TS_BRACKET_REGEX.search(line)
    if not m_ts:
        if args.debug:
            print(f"[DEBUG] No TS match: {line.strip()}", file=sys.stderr)
        return False
    ts = parse_timestamp(m_ts.group("ts"))
    if ts is None:
        if args.debug:
            print(f"[DEBUG] TS parse failed: {m_ts.group('ts')}", file=sys.stderr)
        return False
    tz = m_ts.group("tz")
    if args.debug and tz != "UTC":
        print(f"[DEBUG] TS matched with TZ={tz}", file=sys.stderr)

    if args.since_dt and ts < args.since_dt:
        return False

    m_cli = CLIENT_BRACKET_REGEX.search(line)
    if not m_cli:
        if args.debug:
            print(f"[DEBUG] No client match: {line.strip()}", file=sys.stderr)
        return False
    client_ip = m_cli.group("addr")

    minute_key = ts.strftime("%Y-%m-%d %H:%M")
    current_minute = state.get("current_minute")
    minute_counter: Dict[str, int] = state.setdefault("minute_counter", {})
    alerts_already: Dict[Tuple[str, str], bool] = state.setdefault("alerts_already", {})
    parsed_count = state.setdefault("parsed_count", 0)

    if current_minute is None:
        state["current_minute"] = minute_key
        current_minute = minute_key

    if minute_key != current_minute:
        summarize_minute(current_minute, minute_counter, args.top, csv_fh, heading="Minute (closed)")
        minute_counter.clear()
        alerts_already.clear()
        state["current_minute"] = minute_key

    minute_counter[client_ip] = minute_counter.get(client_ip, 0) + 1

    parsed_count += 1
    state["parsed_count"] = parsed_count
    if args.print_first and parsed_count <= args.print_first:
        print(f"[DEBUG] parsed {parsed_count}: {minute_key} {client_ip}", file=sys.stderr)

    if args.qpm_threshold and minute_counter[client_ip] >= args.qpm_threshold:
        key = (minute_key, client_ip)
        if not alerts_already.get(key):
            print(f"[ALERT] {minute_key} {client_ip} QPM >= {args.qpm_threshold} (now {minute_counter[client_ip]})")
            sys.stdout.flush()
            alerts_already[key] = True
    return True

def main():
    ap = argparse.ArgumentParser(description="Technitium DNS per-client per-minute monitor (daily rotating logs)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--logfile", help="Path to a single log file")
    src.add_argument("--logdir", help="Directory containing rotating daily logs")
    ap.add_argument("--pattern", default="*.log", help="Glob pattern for logs in --logdir (e.g. queries_*.log)")
    ap.add_argument("--qpm-threshold", type=int, default=0, help="Alert if a client hits >= threshold QPM (0=off)")
    ap.add_argument("--top", type=int, default=20, help="Show top-N clients per minute")
    ap.add_argument("--output-csv", help="Append results to CSV (minute,client,qpm)")
    ap.add_argument("--since", help="Only process lines at/after ISO time YYYY-mm-dd HH:MM")
    ap.add_argument("--scan-interval", type=float, default=2.0, help="Seconds between checks for newer logs in --logdir")
    ap.add_argument("--from-beginning", action="store_true", help="Read from start of file instead of tailing from EOF")
    ap.add_argument("--once", action="store_true", help="Read current file once and exit (for testing)")
    ap.add_argument("--debug", action="store_true", help="Verbose debug output to stderr")
    ap.add_argument("--tick", type=float, default=0.0, help="Every N seconds, print a live snapshot of current minute (0=off)")
    ap.add_argument("--print-first", type=int, default=0, help="Print first N parsed lines (minute ip) to stderr")
    args = ap.parse_args()

    args.since_dt = None
    if args.since:
        try:
            args.since_dt = datetime.strptime(args.since, "%Y-%m-%d %H:%M")
        except ValueError:
            print("Invalid --since format. Use: YYYY-mm-dd HH:MM", file=sys.stderr)
            sys.exit(2)

    csv_fh = None
    if args.output_csv:
        csv_exists = os.path.exists(args.output_csv)
        csv_fh = open(args.output_csv, "a", encoding='utf-8')
        if not csv_exists:
            csv_fh.write("minute,client,qpm\n")
            csv_fh.flush()

    state = {"current_minute": None, "minute_counter": {}, "alerts_already": {}, "parsed_count": 0}
    last_tick = time.time()

    def finalize():
        if state["current_minute"] and state["minute_counter"]:
            summarize_minute(state["current_minute"], state["minute_counter"], args.top, csv_fh, heading="Minute (final)")
        if csv_fh:
            csv_fh.close()

    def maybe_tick():
        nonlocal last_tick
        if args.tick and (time.time() - last_tick) >= args.tick and state["minute_counter"]:
            summarize_minute(state["current_minute"], state["minute_counter"], args.top, csv_fh, heading="Minute (live)")
            last_tick = time.time()

    # Single file mode
    if args.logfile:
        if args.once:
            if args.debug: print(f"[DEBUG] Reading once: {args.logfile}", file=sys.stderr)
            for line in iter_file_once(args.logfile):
                process_line(line, args, state, csv_fh)
            finalize()
            return
        if args.debug: print(f"[DEBUG] Tailing: {args.logfile} (from_beginning={args.from_beginning})", file=sys.stderr)
        for line in tail_file(args.logfile, from_beginning=args.from_beginning):
            processed = process_line(line, args, state, csv_fh)
            if processed:
                maybe_tick()
        finalize()
        return

    # Directory mode
    current_path: Optional[str] = None
    current_iter = None
    last_check = 0.0

    while True:
        now = time.time()
        if current_path is None or (now - last_check) >= args.scan_interval:
            last_check = now
            latest = pick_latest_file(args.logdir, args.pattern, debug=args.debug)
            if latest and latest != current_path:
                if current_path is not None:
                    print(f"\n[INFO] Switching to latest log: {latest}")
                else:
                    print(f"[INFO] Following: {latest}")
                sys.stdout.flush()
                current_path = latest
                if args.once:
                    if args.debug: print(f"[DEBUG] Reading once: {current_path}", file=sys.stderr)
                    for line in iter_file_once(current_path):
                        process_line(line, args, state, csv_fh)
                    finalize()
                    return
                current_iter = tail_file(current_path, from_beginning=args.from_beginning)

        if current_iter is None:
            time.sleep(args.scan_interval)
            continue

        try:
            for _ in range(200):
                line = next(current_iter)
                processed = process_line(line, args, state, csv_fh)
                if processed:
                    maybe_tick()
        except StopIteration:
            time.sleep(0.1)
        except KeyboardInterrupt:
            break

    finalize()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
