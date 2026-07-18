# portsweep

A fast **async TCP port scanner in pure Python** — no nmap, no dependencies,
no root required.

`portsweep` uses `asyncio` to run hundreds or thousands of concurrent TCP
`connect()` scans. It resolves the target, sweeps the requested ports, names the
service for each open one, and can grab a banner to fingerprint the software
behind it.

This is a **connect scan**: it completes the full TCP handshake, so results are
accurate and it runs without privileges — but it's not stealthy (the connection
shows up in the target's logs).

## Demo

<!-- Record a scan of scanme.nmap.org with --banner, then drop the file here.
     Replace this line with:  ![portsweep demo](demo.gif) -->

_Demo GIF coming soon._

## Why

Wrapping `nmap` is easy; understanding what a port scan actually *is* — sockets,
concurrency, timeouts, banner grabbing — is the part worth showing. portsweep is
a few hundred lines of readable async Python that does the real thing.

## Install

```bash
git clone https://github.com/<you>/portsweep
cd portsweep
```

No pip install — Python 3 standard library only.

## Usage

```bash
python3 portsweep.py scanme.nmap.org                       # top ~25 common ports
python3 portsweep.py 10.0.0.1 -p 1-1024                     # a range
python3 portsweep.py example.com -p 22,80,443,8080 --banner # specific ports + banner
python3 portsweep.py example.com -p- --concurrency 1000     # all 65535 ports
python3 portsweep.py example.com --json                     # machine-readable
```

### Options

| Flag | Meaning |
|---|---|
| `-p, --ports` | `top` (default), `-` for all 65535, or a spec like `22,80,1-1024` |
| `-c, --concurrency` | max simultaneous connections (default 500) |
| `-t, --timeout` | per-port connect timeout in seconds (default 2.0) |
| `--banner` | attempt a banner grab on each open port |
| `--json` | emit JSON instead of the human report |

## Example

```
== portsweep: scanme.nmap.org (45.33.32.156) ==
scanning 2 ports, concurrency=500, timeout=2.0s

2 open:
    22/tcp  ssh
        └─ SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
    80/tcp  http

done in 1.34s
```

## How it works

1. Resolve the target with `socket.gethostbyname`
2. Parse the port spec into a list
3. Launch one `asyncio.open_connection` coroutine per port, gated by a
   `Semaphore` so concurrency stays bounded
4. A successful handshake = open; optionally read up to 128 bytes for a banner
5. Map each open port to a service name via `socket.getservbyport`

Scanning 1000 ports against a local host completes in a fraction of a second;
the concurrency limit keeps you from exhausting file descriptors on huge sweeps.

## Legal

Only scan hosts you own or are explicitly authorized to test. Unauthorized port
scanning may be illegal in your jurisdiction. `scanme.nmap.org` is a host the
Nmap project provides specifically for testing scanners — use it freely.

## License

MIT
