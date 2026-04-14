"""
api.py — Flask REST + SSE API consumed by the dashboard.

Endpoints
─────────
GET  /api/status          — server health + current config
POST /api/send            — fire one packet  {message, mode}
GET  /api/events          — SSE stream of live events
GET  /api/metrics/<mode>  — current stats for "vpn" or "direct"
POST /api/config          — update latency/loss/bw at runtime
POST /api/reset           — clear all metrics + event log
"""
import sys, os, threading, time, json
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, Response, send_from_directory
import event_log, state, client as vpn_client
import server as vpn_server
import destination as vpn_dest
from config import (CLIENT_VIP, VPN_SERVER_VIP, DEST_SERVER_VIP,
                    VPN_PORT, DEST_PORT, API_PORT)

app = Flask(__name__, static_folder="static")

# ── Start simulation servers in background threads ────────────────────────────
def _boot():
    time.sleep(0.3)
    threading.Thread(target=vpn_dest.start, daemon=True).start()
    time.sleep(0.2)
    threading.Thread(target=vpn_server.start, daemon=True).start()
    event_log.push("system_ready",
        vpn_port=VPN_PORT, dest_port=DEST_PORT,
        client_ip=CLIENT_VIP, vpn_ip=VPN_SERVER_VIP,
        dest_ip=DEST_SERVER_VIP)

threading.Thread(target=_boot, daemon=True).start()

# ── CORS helper (no flask-cors needed) ───────────────────────────────────────
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp

@app.after_request
def after(r): return _cors(r)

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/status")
def status():
    cfg = state.get_cfg()
    return jsonify({
        "ok": True,
        "config": cfg,
        "ips": {
            "client":      CLIENT_VIP,
            "vpn_server":  VPN_SERVER_VIP,
            "destination": DEST_SERVER_VIP,
        },
        "ports": {"vpn": VPN_PORT, "dest": DEST_PORT},
    })

@app.route("/api/send", methods=["POST", "OPTIONS"])
def send():
    if request.method == "OPTIONS": return jsonify({}), 200
    body    = request.json or {}
    message = body.get("message", "ping").strip() or "ping"
    mode    = body.get("mode", "vpn")
    if mode not in ("vpn","direct"):
        return jsonify({"error":"mode must be vpn or direct"}), 400
    result = vpn_client.send(message, mode)
    return jsonify(result)

@app.route("/api/metrics/<mode>")
def metrics(mode):
    if mode not in ("vpn","direct"):
        return jsonify({"error":"unknown mode"}), 400
    return jsonify(state.get_metrics(mode))

@app.route("/api/config", methods=["POST","OPTIONS"])
def update_config():
    if request.method == "OPTIONS": return jsonify({}), 200
    body = request.json or {}
    kw   = {}
    if "latency_ms"  in body: kw["latency_ms"]  = float(body["latency_ms"])
    if "loss_rate"   in body: kw["loss_rate"]    = float(body["loss_rate"])
    if "bw_kbps"     in body: kw["bw_kbps"]      = float(body["bw_kbps"])
    state.set_cfg(**kw)
    event_log.push("config_update", **kw)
    return jsonify({"ok": True, "config": state.get_cfg()})

@app.route("/api/reset", methods=["POST","OPTIONS"])
def reset():
    if request.method == "OPTIONS": return jsonify({}), 200
    state.reset_all()
    event_log.clear()
    event_log.push("reset", note="All metrics and events cleared")
    return jsonify({"ok": True})

@app.route("/api/events")
def events():
    """SSE stream — pushes new events every 300 ms."""
    def generate():
        last_id = 0
        yield "data: {\"kind\":\"connected\"}\n\n"
        while True:
            batch = event_log.since(last_id)
            for e in batch:
                last_id = max(last_id, e["id"])
                yield f"data: {json.dumps(e)}\n\n"
            time.sleep(0.3)
    return Response(generate(),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache",
                             "X-Accel-Buffering":"no"})

if __name__ == "__main__":
    print(f"\n VPN-Sim API  →  http://127.0.0.1:{API_PORT}\n")
    app.run(host="0.0.0.0", port=API_PORT, debug=False, threaded=True)
