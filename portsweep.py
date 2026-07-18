#!/usr/bin/env python3
"""
portsweep — a fast async TCP port scanner in pure Python.

No nmap, no dependencies — just asyncio doing thousands of concurrent TCP
connect() scans. Resolves the target, sweeps the requested ports, names the
service for each open one, and optionally grabs a banner.

This is a "connect scan": it completes the TCP handshake, so it's accurate and
needs no root — but it's not stealthy (the connection is logged by the target).

Usage:
    python3 portsweep.py scanme.nmap.org
    python3 portsweep.py 10.0.0.1 -p 1-1024
    python3 portsweep.py example.com -p 22,80,443,8080 --banner
    python3 portsweep.py example.com -p- --concurrency 1000     # all 65535
    python3 portsweep.py example.com --json

Standard library only — no pip install required.
"""

import argparse
import asyncio
import json
import socket
import sys
import time

# A small set of well-known ports for the default "top ports" scan.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]


class C:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


def color(t, c, on=True):
    return f"{c}{t}{C.END}" if on else t


# ---- port-spec parsing ---------------------------------------------------

def parse_ports(spec):
    """Turn '22,80,1000-1010' (or '-' for all) into a sorted list of ints."""
    if spec in ("-", "all"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi or lo < 1 or hi > 65535:
                raise ValueError(f"bad port range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of range: {p}")
            ports.add(p)
    return sorted(ports)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "?"


# ---- scanning ------------------------------------------------------------

async def scan_port(host, port, sem, timeout, grab_banner):
    """Try to connect. Return a result dict if open, else None."""
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

        banner = None
        if grab_banner:
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=1.0)
                banner = data.decode("utf-8", errors="replace").strip() or None
            except (asyncio.TimeoutError, OSError):
                banner = None

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

        return {"port": port, "service": service_name(port), "banner": banner}


async def sweep(host, ports, concurrency, timeout, grab_banner):
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_port(host, p, sem, timeout, grab_banner) for p in ports]
    results = []
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r:
            results.append(r)
    return sorted(results, key=lambda r: r["port"])


# ---- main ----------------------------------------------------------------

def resolve(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit(f"error: could not resolve '{target}'")


def main():
    ap = argparse.ArgumentParser(
        description="Fast async TCP port scanner (pure Python, no root needed)."
    )
    ap.add_argument("target", help="hostname or IP to scan")
    ap.add_argument("-p", "--ports", default="top",
                    help="ports: 'top' (default), '-' for all, or '22,80,1-1024'")
    ap.add_argument("-c", "--concurrency", type=int, default=500,
                    help="max simultaneous connections (default 500)")
    ap.add_argument("-t", "--timeout", type=float, default=2.0,
                    help="per-port connect timeout in seconds (default 2.0)")
    ap.add_argument("--banner", action="store_true",
                    help="attempt a banner grab on each open port")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of the human report")
    args = ap.parse_args()

    if args.ports == "top":
        ports = TOP_PORTS
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError as e:
            sys.exit(f"error: {e}")

    ip = resolve(args.target)
    on = sys.stdout.isatty() and not args.json

    if not args.json:
        print(color(f"\n== portsweep: {args.target} ({ip}) ==", C.BOLD + C.CYAN, on))
        print(color(f"scanning {len(ports)} ports, "
                    f"concurrency={args.concurrency}, timeout={args.timeout}s",
                    C.GREY, on))

    start = time.monotonic()
    results = asyncio.run(
        sweep(ip, ports, args.concurrency, args.timeout, args.banner)
    )
    elapsed = time.monotonic() - start

    if args.json:
        print(json.dumps({
            "target": args.target,
            "ip": ip,
            "scanned": len(ports),
            "elapsed_seconds": round(elapsed, 2),
            "open": results,
        }, indent=2))
    else:
        if results:
            print(color(f"\n{len(results)} open:", C.GREEN + C.BOLD, on))
            for r in results:
                line = f"  {r['port']:>5}/tcp  {r['service']}"
                print(color(line, C.GREEN, on))
                if r["banner"]:
                    print(color(f"         └─ {r['banner']}", C.GREY, on))
        else:
            print(color("\nno open ports found.", C.GREY, on))
        print(color(f"\ndone in {elapsed:.2f}s\n", C.GREY, on))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
