# IP-Checker

A Linux daemon that enforces, at the network layer, which destination IP
ranges a set of configured domains may be reached through. It exists to
catch traffic that bypasses a system proxy or VPN: regardless of which
application makes a connection or how (system proxy, direct connect, a
custom DNS resolver, DNS-over-HTTPS, a hardcoded IP), if the domain is
listed in the config, the daemon inspects the real destination IP on the
wire and silently drops the connection if that IP falls outside the
domain's allowed CIDR ranges. Domains not listed in the config are left
untouched; only a warning is logged.

## How it works

Two nftables rules queue outbound traffic into user space via NFQUEUE:

- **DNS observer** (`udp`/`tcp dport 53`): parses A-record answers and
  records `resolved IP -> domain` in a short-lived correlation table. DNS
  traffic itself is never blocked.
- **TLS/SNI observer** (`tcp dport 443`): on a new connection's SYN packet,
  checks the DNS correlation table first — if the destination IP is already
  known to violate a configured domain's allowed ranges, the SYN itself is
  dropped before it ever leaves the machine. Otherwise, TCP segments are
  reassembled until a full TLS ClientHello is available, its SNI extension
  is parsed to learn the real hostname, and the connection is dropped if
  that hostname is configured with CIDRs that exclude the destination IP.
  A per-flow verdict cache means this happens once per connection, not once
  per packet.

Both nftables rules use `bypass`, so if the daemon is not running or
crashes, matched traffic falls through unfiltered rather than stalling —
the daemon fails open, not closed.

## Building

Requires Go 1.22 or newer.

```
make build
```

## Configuration

Config is a single JSON file. See `configs/config.example.json` for a
complete example using Cloudflare's published IPv4 ranges.

```json
{
  "log": { "level": "warn", "path": "stdout" },
  "nfqueue": { "dns_queue_num": 100, "tls_queue_num": 101 },
  "enforcement_mode": "enforce",
  "dns_correlation_ttl_seconds": 300,
  "flow_verdict_ttl_seconds": 600,
  "cidr_sets": {
    "cloudflare-ipv4": ["104.16.0.0/13", "172.64.0.0/13"]
  },
  "domains": [
    { "domain": "claude.ai", "cidr_sets": ["cloudflare-ipv4"] },
    { "domain": "*.anthropic.com", "cidr_sets": ["cloudflare-ipv4"] }
  ]
}
```

- `domain` entries are exact matches unless prefixed with `*.`, which
  matches any subdomain at any depth (but not the apex domain itself —
  list both `example.com` and `*.example.com` if both should be covered).
- `cidr_sets` are named, reusable CIDR lists referenced by domains via
  `cidr_sets`, or a domain can list `cidrs` inline, or both.
- `enforcement_mode: "monitor"` evaluates and logs every decision exactly
  as `"enforce"` would, but never actually drops a packet. Run in this mode
  first against real traffic to check for false positives before switching
  to `"enforce"`.
- Cloudflare's IPv4 ranges change occasionally; refresh
  `cidr_sets.cloudflare-ipv4` periodically from
  `https://www.cloudflare.com/ips-v4`.

Sending `SIGHUP` to the running daemon (or `systemctl reload ip-checker`)
reloads the config file. If the new config fails to parse or validate, the
previous config keeps running and the error is logged.

## Installing

```
sudo make install
sudo systemctl enable --now ip-checker
```

This installs the binary to `/usr/local/bin/ipcheckerd`, the systemd unit
to `/etc/systemd/system/ip-checker.service`, and a starter config to
`/etc/ip-checker/config.json` (only if one does not already exist there).
Edit that file before enabling the service.

`sudo make uninstall` reverses this.

## Manual verification

Run in `enforcement_mode: "monitor"` first and check the logs against real
traffic before switching to `"enforce"`. `curl --resolve` lets you force a
destination IP regardless of real DNS, without needing extra infrastructure:

```
# Allowed: 104.18.30.20 is inside a configured Cloudflare range
curl -v --resolve claude.ai:443:104.18.30.20 https://claude.ai/ --max-time 5

# Blocked: 8.8.8.8 is outside every configured CIDR
curl -v --resolve claude.ai:443:8.8.8.8 https://claude.ai/ --max-time 5
# expect: curl hangs to --max-time with no response (a silent drop, not a
# TCP reset), and the daemon logs an "event":"block" entry

# Passthrough: a domain absent from the config is never touched
curl -v --resolve example.org:443:<real-ip> https://example.org/ --max-time 5
# expect: succeeds normally, and the daemon logs "event":"passthrough_unmonitored"
```

To confirm fail-open behavior, kill the daemon (`sudo kill -9 <pid>`) mid-test
and confirm new HTTPS connections keep working immediately, then confirm
`sudo nft list ruleset` no longer shows the `ipchecker` table once
`systemctl` finishes stopping it.

## Known limitations

- **QUIC / HTTP3 (UDP/443)**: not intercepted in this version. A browser
  that opportunistically upgrades a Cloudflare-fronted connection to QUIC
  bypasses TLS/SNI enforcement entirely, since only `tcp dport 443` is
  queued. Until QUIC Initial-packet SNI parsing is implemented, the
  practical mitigation is blocking outbound UDP/443 system-wide (forcing a
  TCP fallback), which this daemon does not do on its own.
- **Encrypted Client Hello (ECH)**: if negotiated, the real SNI is
  encrypted and only a decoy name (if any) is visible on the wire.
- **No SNI present**: rare with modern TLS stacks; the connection is
  allowed through with a debug-level log entry noting no domain could be
  determined.
- **IPv4 only**: IPv6 destinations are not evaluated in this version.
