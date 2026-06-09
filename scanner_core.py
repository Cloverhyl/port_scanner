import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple


TOP20 = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,3306,3389,5432,5900]


# common port -> service name mapping (used for simple inference)
PORT_SERVICE = {
    21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 111: 'RPC', 135: 'MS-RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC'
}


def parse_targets(target_strs: List[str]) -> Tuple[List[str], List[str]]:
    """Parse list of target strings (IP, CIDR, or range) into list of IP strings.

    Returns a tuple (valid_ips, invalid_entries).
    Invalid entries are returned so callers can show friendly messages.
    """
    results = []
    invalids = []
    for s in target_strs:
        raw = s
        s = s.strip()
        if not s:
            continue
        if '/' in s:
            # CIDR
            try:
                net = ipaddress.ip_network(s, strict=False)
                # skip very large networks for safety
                hosts = list(net.hosts())
                if len(hosts) > 65536:
                    invalids.append(raw)
                    continue
                results.extend([str(ip) for ip in hosts])
            except Exception:
                invalids.append(raw)
                continue
        elif '-' in s:
            # Range: start-end
            try:
                a, b = s.split('-', 1)
                start = ipaddress.ip_address(a.strip())
                end = ipaddress.ip_address(b.strip())
                cur = int(start)
                last = int(end)
                if cur > last:
                    cur, last = last, cur
                # limit range size for safety
                if last - cur > 65536:
                    invalids.append(raw)
                    continue
                for n in range(cur, last + 1):
                    results.append(str(ipaddress.ip_address(n)))
            except Exception:
                invalids.append(raw)
                continue
        else:
            # single IP
            try:
                ipaddress.ip_address(s)
                results.append(s)
            except Exception:
                invalids.append(raw)
                continue
    # dedupe while preserving order
    seen = set()
    out = []
    for ip in results:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out, invalids


def is_port_open(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def detect_services(open_ports: List[int]) -> List[str]:
    """Given a list of open ports, return a list of inferred service names."""
    services = []
    for p in sorted(open_ports):
        name = PORT_SERVICE.get(p)
        if name:
            services.append(name)
        else:
            services.append(f'未知({p})')
    return services


def scan_host_ports(ip: str, ports: List[int], concurrency: int = 5, timeout: float = 1.0) -> Tuple[List[int], int]:
    """Scan given ports on a host. Returns (open_ports, elapsed_ms)."""
    start = time.time()
    open_ports = []
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(is_port_open, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    elapsed_ms = int((time.time() - start) * 1000)
    open_ports.sort()
    return open_ports, elapsed_ms


if __name__ == '__main__':
    print('scanner_core.py: helper module - not intended to run directly')
