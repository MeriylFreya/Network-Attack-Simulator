# app.py
import threading
import time
import json
from collections import deque, Counter, defaultdict
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import socket

# Optional: scapy for real packet capture
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception as e:
    print(f"Warning: scapy not available. Real capture disabled. Error: {e}")
    SCAPY_AVAILABLE = False

# Config
SNAPSHOT_WINDOW = 30
EMIT_INTERVAL = 0.5
UDP_ECHO_PORT = 9999

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netlab-pro-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Data stores
per_second = deque(maxlen=SNAPSHOT_WINDOW)
protocol_counter = Counter()
top_talkers = defaultdict(lambda: {"bytes": 0, "packets": 0})
recent_packets = deque(maxlen=50)
lock = threading.Lock()

# Generator control
generator_running = False
sniffer_running = False
stop_event = threading.Event()

def now_sec():
    return int(time.time())

def add_packet(pkt_info):
    ts = int(pkt_info['ts'])
    with lock:
        if not per_second or per_second[-1]['ts'] != ts:
            per_second.append({"ts": ts, "bytes": pkt_info['bytes'], "packets": 1})
        else:
            per_second[-1]['bytes'] += pkt_info['bytes']
            per_second[-1]['packets'] += 1
        
        protocol_counter[pkt_info['proto']] += 1
        key = f"{pkt_info['src']}"
        top_talkers[key]['bytes'] += pkt_info['bytes']
        top_talkers[key]['packets'] += 1
        recent_packets.appendleft(pkt_info)

def scapy_packet_to_info(pkt):
    try:
        proto = "OTHER"
        src = "unknown"
        dst = "unknown"
        size = len(pkt)
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if TCP in pkt:
                proto = "TCP"
            elif UDP in pkt:
                proto = "UDP"
            elif ICMP in pkt:
                proto = "ICMP"
        
        return {
            "ts": time.time(),
            "src": src,
            "dst": dst,
            "proto": proto,
            "bytes": size,
            "summary": pkt.summary() if hasattr(pkt, 'summary') else str(pkt)[:50]
        }
    except Exception as e:
        return {
            "ts": time.time(),
            "src": "error",
            "dst": "error",
            "proto": "ERROR",
            "bytes": 0,
            "summary": f"Parse error: {e}"
        }

def scapy_sniff_worker(iface=None):
    global sniffer_running
    if not SCAPY_AVAILABLE:
        return
    sniffer_running = True
    print(f"[sniffer] Starting on interface {iface}")
    try:
        sniff(iface=iface, prn=lambda p: add_packet(scapy_packet_to_info(p)), store=False)
    except Exception as e:
        print(f"Sniffer error: {e}")
    finally:
        sniffer_running = False

def udp_generator(target_ip="127.0.0.1", target_port=UDP_ECHO_PORT, pps=300, payload_size=200):
    global generator_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = 1.0 / max(1, pps)
    
    print(f"[generator] Starting to {target_ip}:{target_port} at {pps}pps")
    
    while generator_running and not stop_event.is_set():
        seq += 1
        ts = time.time()
        payload = json.dumps({"seq": seq, "ts": ts}).encode('utf-8').ljust(payload_size, b'0')
        
        try:
            sock.sendto(payload, (target_ip, target_port))
            add_packet({
                "ts": ts,
                "src": "127.0.0.1",
                "dst": target_ip,
                "proto": "UDP",
                "bytes": len(payload),
                "summary": f"Generated UDP seq={seq}"
            })
        except Exception as e:
            print(f"Generator error: {e}")
        
        if stop_event.wait(interval):
            break
    
    sock.close()
    print("[generator] Stopped")

def emitter_loop():
    while True:
        time.sleep(EMIT_INTERVAL)
        with lock:
            times = [p['ts'] for p in per_second]
            bytes_series = [p['bytes'] for p in per_second]
            packets_series = [p['packets'] for p in per_second]
            proto_counts = dict(protocol_counter.most_common(10))
            
            talkers = sorted(top_talkers.items(), key=lambda kv: kv[1]['bytes'], reverse=True)[:10]
            talkers_list = [{"ip": k, "bytes": v['bytes'], "packets": v['packets']} for k, v in talkers]
            
            recent = [
                {
                    "time": time.strftime('%H:%M:%S', time.localtime(p['ts'])),
                    "proto": p['proto'],
                    "src": p['src'],
                    "dst": p['dst'],
                    "size": p['bytes']
                }
                for p in list(recent_packets)[:10]
            ]
            
            current_throughput = bytes_series[-1] if bytes_series else 0
            current_pps = packets_series[-1] if packets_series else 0
        
        socketio.emit('stats', {
            "times": times,
            "throughput": bytes_series,
            "pps": packets_series,
            "protocols": proto_counts,
            "top_talkers": talkers_list,
            "recent_packets": recent,
            "kpis": {
                "throughput": int(current_throughput),
                "pps": int(current_pps),
                "protocol_count": len(proto_counts),
                "active_connections": len(top_talkers)
            }
        })

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def on_connect():
    emit('connected', {'status': 'connected'})

@socketio.on('start_generator')
def on_start_generator(data):
    global generator_running
    if generator_running:
        emit('generator_status', {'running': True})
        return
    
    stop_event.clear()
    target = data.get('target', '127.0.0.1')
    pps = int(data.get('pps', 300))
    size = int(data.get('size', 200))
    
    generator_running = True
    threading.Thread(target=udp_generator, args=(target, UDP_ECHO_PORT, pps, size), daemon=True).start()
    emit('generator_status', {'running': True})

@socketio.on('stop_generator')
def on_stop_generator():
    global generator_running
    generator_running = False
    stop_event.set()
    emit('generator_status', {'running': False})

@socketio.on('start_sniff')
def on_start_sniff(data):
    if not SCAPY_AVAILABLE:
        emit('sniffer_status', {'running': False, 'error': 'Scapy not available'})
        return
    
    iface = data.get('iface') or None
    threading.Thread(target=scapy_sniff_worker, args=(iface,), daemon=True).start()
    emit('sniffer_status', {'running': True})

if __name__ == '__main__':
    # Start emitter
    threading.Thread(target=emitter_loop, daemon=True).start()
    
    print("Starting NetLab Pro Dashboard on http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)