"""
state.py — Shared mutable runtime state (config + per-mode metrics).
"""
import threading, time

_lock = threading.Lock()

def _blank():
    return {"sent":0,"recv":0,"dropped":0,
            "bytes_plain":0,"bytes_enc":0,
            "rtts":[],"start":time.time()}

_cfg = {"latency_ms":80,"loss_rate":0.10,"bw_kbps":1000,"mode":"vpn"}

_metrics = {"vpn": _blank(), "direct": _blank()}

def get_cfg():
    with _lock: return dict(_cfg)

def set_cfg(**kw):
    with _lock:
        for k,v in kw.items():
            if k in _cfg: _cfg[k]=v

def record_sent(mode,plain,enc):
    with _lock:
        m=_metrics[mode]; m["sent"]+=1; m["bytes_plain"]+=plain; m["bytes_enc"]+=enc

def record_recv(mode,rtt):
    with _lock:
        m=_metrics[mode]; m["recv"]+=1; m["rtts"].append(round(rtt,1))
        if len(m["rtts"])>100: m["rtts"].pop(0)

def record_drop(mode):
    with _lock: _metrics[mode]["dropped"]+=1

def get_metrics(mode):
    with _lock:
        m=_metrics[mode]
        elapsed=max(time.time()-m["start"],0.001)
        rtts=m["rtts"]
        return {
            "sent":m["sent"],"recv":m["recv"],"dropped":m["dropped"],
            "loss_pct":round(m["dropped"]/m["sent"]*100,1) if m["sent"] else 0,
            "bytes_plain":m["bytes_plain"],"bytes_enc":m["bytes_enc"],
            "overhead_pct":round((m["bytes_enc"]-m["bytes_plain"])/m["bytes_plain"]*100,1)
                           if m["bytes_plain"] else 0,
            "throughput_kbps":round(m["bytes_enc"]*8/elapsed/1000,2),
            "avg_rtt_ms":round(sum(rtts)/len(rtts),1) if rtts else 0,
            "rtt_samples":list(rtts[-30:]),
            "elapsed_s":round(elapsed,1),
        }

def reset_all():
    with _lock:
        for mode in ("vpn","direct"):
            _metrics[mode]=_blank()
