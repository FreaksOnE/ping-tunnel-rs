# ping-tunnel-rs

Build: `cargo build --release`
Tests: `cargo test`

## Server usage (root required)

The server owns the raw ICMP socket and the TUN device and must run as root.

1. Run: `sudo ./target/release/ping-tunnel-rs server --clients <uuid>:<password>[,<uuid>:<password>...]`
   - On start the server enables `net.ipv4.ip_forward` and installs the
     iptables rules that make it a gateway for the tunnel subnet — a
     masquerade out of `--out-interface` (default `eth0`) plus the two FORWARD
     accepts — and removes them again on exit. With `--skip-nat` it leaves
     forwarding and the firewall to you:
     ```sh
     sysctl -w net.ipv4.ip_forward=1
     iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o <wan-if> -j MASQUERADE
     iptables -A FORWARD -i tun0 -o <wan-if> -j ACCEPT
     iptables -A FORWARD -i <wan-if> -o tun0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
     ```
   - `uuid:password` pairs are comma-separated; the server trial-decrypts auth
     requests against the derived keys and routes client traffic.
   - `--tun-name <name>` creates the TUN at 10.10.10.1/24 with the full outer
     MTU. The FORWARD rules reference that name.
   - Kernel ICMP echo replies are suppressed while running and restored on exit.
   - The auth request carries the client id only, so one
     client id holds exactly one session: a new successful auth for the same
     client id replaces the old one.
   - `--session-timeout <SECONDS>` (default 60) drops a session that received
     nothing from its client for that long: the tun octet is freed for reuse and
     the client is told to re-authenticate. Traffic from that client is rejected
     with the same notice until it does — never silently black-holed.

## Client usage (root required)

```sh
sudo ./target/release/ping-tunnel-rs client \
  --client-id <uuidv7> --password <password> --server-ip <server-outer-ip>
```

- `--client-id` must be a uuid v7 registered in the server allowlist.
- The TUN (default `tun0`) is created at 10.10.10.<octet> (assigned by the
  server) with MTU `outer_mtu - 72`.
- When the server drops the session (`--session-timeout`) the client
  re-authenticates on its own and keeps running; a client that the server cannot
  serve again exits with a typed error like any other failed auth.
- The TUN device is kept when the server hands out the same octet again (the usual
  case), so routes into the tunnel survive a re-authentication; a different octet
  replaces the device — the client re-applies its default route automatically,
  but routes you added by hand have to be re-applied.
- Unless `--skip-route` (`-r`) is given, the client replaces the IPv4 default
  route with the tunnel once the session is up and restores the original
  default routes when it exits (also on a fatal error). The server's outer IP
  is pinned outside the tunnel first (a /32 via the previous default route),
  so the ICMP transport never loops into the tunnel. Route management needs
  iproute2 (`ip`); with `--skip-route` you route the destinations you want
  tunneled into the TUN yourself.
