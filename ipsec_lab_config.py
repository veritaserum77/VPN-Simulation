"""
Central configuration for 4-laptop IPsec simulation.

Update these values once for your lab, then run scripts without long IP arguments.
"""

# -----------------------------
# Laptop 1: VPN Gateway Server
# -----------------------------
# Bind host used by VPN server process. Keep 0.0.0.0 unless you need to restrict interface.
VPN_SERVER_BIND_HOST = "0.0.0.0"
# VPN server listening port.
VPN_SERVER_PORT = 7000
# Real LAN IP of Laptop 1 (VPN server). Clients connect to this IP.
VPN_SERVER_IP = "10.130.98.159"

# -----------------------------
# Laptop 2: Destination Server
# -----------------------------
# Bind host used by destination server process.
DEST_SERVER_BIND_HOST = "0.0.0.0"
# Destination server listening port.
DEST_SERVER_PORT = 7100
# Real LAN IP of Laptop 2 (destination server). VPN server forwards to this IP.
DEST_SERVER_IP = "10.130.98.160"

# -----------------------------
# Authentication users at VPN
# -----------------------------
# Format: "username:password,username2:password2"
VPN_USERS = "client1:secure123"
