"""
config.py — Global constants for VPN-Sim
"""

# UDP transport (loopback)
SERVER_IP   = "127.0.0.1"
VPN_PORT    = 5100          # VPN server listens here
DEST_PORT   = 5101          # destination server listens here
API_PORT    = 5200          # Flask dashboard API

BUFFER_SIZE = 8192

# WAN simulation defaults (overridable at runtime via API)
LATENCY_MS     = 80
PACKET_LOSS    = 0.10
BANDWIDTH_KBPS = 1000

# AES-256-GCM — 32-byte key
KEY = b'VpnSimSecureKey!VpnSimSecureKey!'

# Protocol
PROTOCOL_VERSION = b'\x01'

# Virtual IPs — application-layer identity only
CLIENT_VIP      = "10.0.0.2"
VPN_SERVER_VIP  = "10.0.0.1"
DEST_SERVER_VIP = "93.184.216.34"
