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
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
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
    """
    Convert Scapy packet to info dict
    Now supports TCP, UDP, ICMP, ARP, and other protocols
    """
    try:
        proto = "OTHER"
        src = "unknown"
        dst = "unknown"
        size = len(pkt)
        
        # Check for IP layer first
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Identify specific protocols
            if TCP in pkt:
                proto = "TCP"
                # Optionally add port info
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                src = f"{src}:{src_port}"
                dst = f"{dst}:{dst_port}"
            elif UDP in pkt:
                proto = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                src = f"{src}:{src_port}"
                dst = f"{dst}:{dst_port}"
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                # Check protocol number
                proto_num = pkt[IP].proto
                proto_map = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                    41: "IPv6",
                    47: "GRE",
                    50: "ESP",
                    51: "AH",
                    89: "OSPF"
                }
                proto = proto_map.get(proto_num, f"IP-{proto_num}")
        
        # Check for ARP (no IP layer)
        elif ARP in pkt:
            proto = "ARP"
            src = pkt[ARP].psrc if hasattr(pkt[ARP], 'psrc') else "unknown"
            dst = pkt[ARP].pdst if hasattr(pkt[ARP], 'pdst') else "unknown"
        
        # For other packet types
        else:
            proto = pkt.name if hasattr(pkt, 'name') else "OTHER"
        
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
    """
    Sniff packets from the network interface
    Captures ALL protocols: TCP, UDP, ICMP, ARP, etc.
    """
    global sniffer_running
    if not SCAPY_AVAILABLE:
        return
    
    sniffer_running = True
    print(f"[sniffer] Starting on interface {iface if iface else 'auto-detect'}")
    socketio.emit('sniffer_status', {'running': True})
    
    try:
        # Sniff without filter to capture all protocols
        sniff(
            iface=iface, 
            prn=lambda p: add_packet(scapy_packet_to_info(p)), 
            store=False,
            # Remove filter to capture all packets
            filter=None
        )
    except Exception as e:
        print(f"Sniffer error: {e}")
        socketio.emit('sniffer_status', {'running': False, 'error': str(e)})
    finally:
        sniffer_running = False
        socketio.emit('sniffer_status', {'running': False})

def udp_generator(target_ip="127.0.0.1", target_port=UDP_ECHO_PORT, pps=300, payload_size=200):
    """
    Generate fake UDP packets for testing
    This creates synthetic traffic to test the dashboard
    """
    global generator_running
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    interval = 1.0 / max(1, pps)
    
    print(f"[generator] Starting FAKE UDP packets to {target_ip}:{target_port} at {pps}pps")
    print(f"[generator] This is SYNTHETIC traffic for testing purposes")
    
    while generator_running and not stop_event.is_set():
        seq += 1
        ts = time.time()
        payload = json.dumps({"seq": seq, "ts": ts, "type": "FAKE"}).encode('utf-8').ljust(payload_size, b'0')
        
        try:
            sock.sendto(payload, (target_ip, target_port))
            add_packet({
                "ts": ts,
                "src": "127.0.0.1",
                "dst": target_ip,
                "proto": "UDP",
                "bytes": len(payload),
                "summary": f"Generated FAKE UDP seq={seq}"
            })
        except Exception as e:
            print(f"Generator error: {e}")
        
        if stop_event.wait(interval):
            break
    
    sock.close()
    generator_running = False
    socketio.emit('generator_status', {'running': False})
    print("[generator] Stopped - Fake UDP generation ended")

def emitter_loop():
    """
    Periodically emit stats to connected clients
    """
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
    emit('generator_status', {'running': generator_running})
    emit('sniffer_status', {'running': sniffer_running})

@socketio.on('start_generator')
def on_start_generator(data):
    """
    Start generating FAKE UDP packets
    This creates synthetic test traffic
    """
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
    print("[API] Fake UDP generator started")

@socketio.on('stop_generator')
def on_stop_generator(data=None):
    """
    Stop generating fake UDP packets
    This stops all synthetic traffic generation
    """
    global generator_running
    generator_running = False
    stop_event.set()
    emit('generator_status', {'running': False})
    print("[API] Fake UDP generator stopped")

@socketio.on('start_sniff')
def on_start_sniff(data):
    """
    Start capturing REAL network packets
    This monitors actual network traffic (all protocols)
    """
    if not SCAPY_AVAILABLE:
        emit('sniffer_status', {'running': False, 'error': 'Scapy not available. Install with: pip install scapy'})
        return
    
    if sniffer_running:
        emit('sniffer_status', {'running': True})
        return
    
    iface = data.get('iface') or None
    threading.Thread(target=scapy_sniff_worker, args=(iface,), daemon=True).start()
    print(f"[API] Real packet capture started on interface: {iface if iface else 'auto'}")

@socketio.on('stop_sniff')
def on_stop_sniff(data=None):
    """
    Stop capturing network packets
    """
    global sniffer_running
    sniffer_running = False
    emit('sniffer_status', {'running': False})
    print("[API] Real packet capture stopped")

if __name__ == '__main__':
    # Start emitter
    threading.Thread(target=emitter_loop, daemon=True).start()
    
    print("=" * 60)
    print("🚀 NetLab Pro Dashboard Starting...")
    print("=" * 60)
    print("📡 Features:")
    print("  • Real packet capture (TCP, UDP, ICMP, ARP, etc.)")
    print("  • Fake UDP traffic generator for testing")
    print("  • Real-time visualization")
    print("=" * 60)
    print("🌐 Access dashboard at: http://localhost:5000")
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)