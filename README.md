# VPN-Sim — Full System with Web Dashboard

A complete VPN simulation with a live web dashboard showing IP masking,
encryption, and VPN vs Direct comparison in real time.

---

## Quick Start

```bash
pip install cryptography flask
python3 api.py
# Open http://localhost:5200 in your browser
```

That one command starts everything — VPN server, destination server, Flask
API, and the dashboard. No separate terminals needed.

---

## Project Structure

```
vpn-sim2/
├── config.py         Virtual IPs, ports, AES key, WAN defaults
├── crypto_utils.py   AES-256-GCM encrypt / decrypt
├── tunnel.py         9-byte tunnel header, encap/decap, WAN simulation
├── packet.py         JSON envelope {src,dst,proto,payload} + NAT rewrite
├── event_log.py      Thread-safe in-memory event bus (SSE → dashboard)
├── state.py          Live config + per-mode metrics (VPN / Direct)
├── destination.py    Simulated internet server (port 5101)
├── server.py         VPN gateway — decrypt, NAT rewrite, re-encrypt (port 5100)
├── client.py         Sends packets in VPN or Direct mode
├── api.py            Flask REST + SSE API + static file server (port 5200)
└── static/
    └── index.html    Dashboard (topology, stats, comparison, live log)
```

---

## What the Dashboard Shows

| Panel | What it proves |
|---|---|
| Mode toggle (VPN / Direct) | Switch between masked and unmasked routing |
| Topology diagram | Live path showing which IP the destination actually sees |
| IP identity cards | CLIENT_VIP, VPN_SERVER_VIP, DEST_SERVER_VIP always visible |
| Stat cards | Sent / Received / Dropped / Avg RTT per mode |
| RTT line chart | VPN adds ~2× latency vs direct (extra hop) |
| Encryption overhead bars | Payload vs 28-byte crypto overhead vs 9-byte header |
| VPN vs Direct table | Side-by-side: IP hidden vs exposed, RTT, loss rate |
| Live event log | Every pipeline stage: NAT rewrite in amber, delivery in green |
| WAN sliders | Adjust latency / packet loss / bandwidth without restart |

---

## The VPN Flow (what happens per packet)

```
CLIENT (10.0.0.2)
  build envelope  {src:10.0.0.2, dst:93.184.216.34, payload:"..."}
  AES-256-GCM encrypt  →  nonce(12B) + ciphertext + GCM tag(16B)
  tunnel encapsulate   →  header(9B) + encrypted payload
  simulate WAN         →  latency + possible packet drop
  UDP → VPN server :5100

VPN SERVER (10.0.0.1)
  decapsulate + decrypt  →  reads src=10.0.0.2
  NAT rewrite            →  src = 10.0.0.1       ← IP MASKING
  re-encrypt + encapsulate
  UDP → destination :5101

DESTINATION (93.184.216.34)
  src_seen = 10.0.0.1   ← CLIENT IS HIDDEN
  sends response back to VPN server

VPN SERVER
  receives response, rewraps for client
  src=10.0.0.1, dst=10.0.0.2
  UDP → client

CLIENT
  decrypts → src_seen = 10.0.0.1   (VPN server, not raw destination)
  RTT measured, dashboard updated
```

## The Direct Flow (no VPN)

```
CLIENT (10.0.0.2)
  same encryption + encapsulation
  UDP → destination :5101  DIRECTLY

DESTINATION
  src_seen = 10.0.0.2   ← CLIENT IP IS EXPOSED
```

---

## Configuration (config.py)

| Setting | Default | Meaning |
|---|---|---|
| `LATENCY_MS` | 30 | One-way WAN delay per hop |
| `PACKET_LOSS` | 0.10 | 10% random drop rate |
| `BANDWIDTH_KBPS` | 1000 | Bandwidth throttle |
| `CLIENT_VIP` | 10.0.0.2 | Client virtual IP |
| `VPN_SERVER_VIP` | 10.0.0.1 | VPN gateway virtual IP |
| `DEST_SERVER_VIP` | 93.184.216.34 | Destination virtual IP |

All WAN parameters are also adjustable live from the dashboard sliders.

---

## Key Design Decisions

| Feature | Implementation | Real VPN equivalent |
|---|---|---|
| Encryption | AES-256-GCM | WireGuard: ChaCha20-Poly1305 |
| Transport | UDP sockets | WireGuard/OpenVPN UDP |
| IP masking | `rewrite_src()` in packet.py | iptables MASQUERADE / WG allowed-IPs |
| Tunnel header | 9-byte (ver+seq+len) | IP-in-IP, GRE, VXLAN |
| WAN simulation | latency + loss + bandwidth | tc netem on Linux |
| Dashboard API | Flask SSE | — |

---

## 4-Laptop IPsec-Style Simulation

This repository now also includes a multi-device simulation with:

- Laptop 1: VPN gateway
- Laptop 2: Destination server
- Laptop 3: Authorized client
- Laptop 4: Unauthorized client

Files used:

- `ipsec_vpn_server.py`
- `ipsec_destination_server.py`
- `ipsec_client_node.py`
- `ipsec_sim_common.py`
- `ipsec_lab_config.py` (edit this once with your real laptop IPs)

### Set global IPs once (recommended)

Open `ipsec_lab_config.py` and edit:

- `VPN_SERVER_IP` = Laptop 1 real LAN IP (clients connect to this)
- `DEST_SERVER_IP` = Laptop 2 real LAN IP (VPN forwards to this)
- `VPN_USERS` = allowed credentials, e.g. `client1:secure123`

After this, most commands can be run without passing IPs explicitly.

All commands below are config-driven and use values from `ipsec_lab_config.py`.

### Install dependency (all laptops)

```bash
pip install cryptography
```

### 1) Laptop 2: Start destination server

```bash
python ipsec_destination_server.py
```

### 2) Laptop 1: Start VPN server

```bash
python ipsec_vpn_server.py
```

### 3) Laptop 3: Authorized client (success path)

ESP mode (encryption + integrity):

```bash
python ipsec_client_node.py --username client1 --password secure123 --mode esp --client-id laptop3-auth --message "Hello via ESP tunnel"
```

AH mode (integrity only):

```bash
python ipsec_client_node.py --username client1 --password secure123 --mode ah --client-id laptop3-auth --message "Hello via AH mode"
```

### 4) Laptop 4: Unauthorized client (reject path)

Use bad credentials to demonstrate failed authentication:

```bash
python ipsec_client_node.py --username attacker --password wrongpass --mode esp --client-id laptop4-unauth --message "Should fail"
```

Expected result: `Authentication failed: unauthorized`

Optional (debug only): You can still override values from config with CLI flags such as `--server-host` or `--dest-host`.

### How this maps to IPsec concepts

- IKE phase 1 key exchange: X25519 DH in auth flow
- IKE authentication: username/password check at VPN server
- ESP: AES-256-GCM encrypted payload + HMAC-SHA256
- AH: plaintext payload + HMAC-SHA256 (no encryption)
- Tunnel mode: inner payload wrapped inside `vpn_data` packet with outer header
- SA-like session: per-client session keys derived and held in VPN process memory

