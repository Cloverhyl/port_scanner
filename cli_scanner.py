import argparse
import os
import sys
import time
from typing import List

from scanner_core import parse_targets, scan_host_ports, detect_services, TOP20
from exporter import write_csv_backup


def parse_ports(s: str) -> List[int]:
    if not s:
        return TOP20
    parts = s.split(',')
    out = []
    invalid = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            val = int(p)
            if 1 <= val <= 65535:
                out.append(val)
            else:
                invalid.append(p)
        except ValueError:
            invalid.append(p)
    if invalid:
        print('Warning: ignored invalid port entries:', ','.join(invalid))
    return out or TOP20


def run_cli(targets_arg: str, ports_arg: str, concurrency: int, timeout: float, export: bool):
    targets = [t.strip() for t in targets_arg.split(',') if t.strip()]
    ips, invalids = parse_targets(targets)
    if invalids:
        print('Warning: ignored invalid target entries:', ','.join(invalids))
    if not ips:
        print('No valid target IPs after parsing. Exiting.', file=sys.stderr)
        return
    ports = parse_ports(ports_arg)
    print(f'Target IPs: {len(ips)} entries')
    records = []
    for ip in ips:
        print(f'Scanning {ip} ...', end=' ', flush=True)
        start = time.time()
        open_ports, elapsed_ms = scan_host_ports(ip, ports, concurrency=concurrency, timeout=timeout)
        duration = int((time.time() - start) * 1000)
        if open_ports:
            print(f'open ports: {open_ports} ({elapsed_ms} ms)')
        else:
            print(f'no open ports ({elapsed_ms} ms)')
        rec = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'target_ip': ip,
            'open_ports': ';'.join(str(p) for p in open_ports),
            'services': ';'.join(detect_services(open_ports)),
            'scanned_ports_count': len(ports),
            'scan_duration_ms': elapsed_ms,
            'notes': ''
        }
        records.append(rec)
    if export:
        out = write_csv_backup(records, dest_dir=os.getcwd())
        print('Backup CSV written to:', out)


def main():
    parser = argparse.ArgumentParser(description='Port scanner (CLI) - minimal test harness')
    parser.add_argument('--gui', action='store_true', help='Launch GUI (PySide6)')
    parser.add_argument('--targets', required=True, help='Comma-separated targets (IP, CIDR, range)')
    parser.add_argument('--ports', default='', help='Comma-separated ports (default Top20)')
    parser.add_argument('--concurrency', type=int, default=5, help='Concurrency (1-50)')
    parser.add_argument('--timeout', type=float, default=1.0, help='Per-port timeout seconds')
    parser.add_argument('--export', action='store_true', help='Export CSV backup to cwd')
    args = parser.parse_args()
    if args.gui:
        # Lazy import GUI to avoid requiring PySide6 for CLI-only runs
        try:
            from app_gui import run as run_gui
        except Exception as e:
            print('Failed to import GUI:', e, file=sys.stderr)
            sys.exit(1)
        run_gui()
    else:
        run_cli(args.targets, args.ports, args.concurrency, args.timeout, args.export)


if __name__ == '__main__':
    main()
