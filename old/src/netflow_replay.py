#!/usr/bin/env python3
import socket
import struct
import time
import dpkt
import sys
from datetime import datetime, timedelta

PCAP_FILE = '/opt/netflow-demo/Netflowv9.pcap'
SYCOPE_IP = '192.168.0.100'
SYCOPE_PORT = 2055
REPLAY_DURATION = 55 * 60  # 55 minutes in seconds

def update_netflow_v9_timestamp(payload):
    """Update Unix timestamp in NetFlow v9 packet"""
    if len(payload) < 20:
        return payload

    data = bytearray(payload)

    # NetFlow v9 header:
    # 0-1: Version (0x0009)
    # 2-3: Count
    # 4-7: SysUptime
    # 8-11: Unix Timestamp (updated here)
    # 12-15: Sequence
    # 16-19: Source ID

    current_timestamp = int(time.time())
    data[8:12] = struct.pack('!I', current_timestamp)

    return bytes(data)

def load_packets():
    """Load UDP NetFlow packets from PCAP"""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Loading packets from {PCAP_FILE}...")
    sys.stdout.flush()

    packets = []
    with open(PCAP_FILE, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        if udp.dport == SYCOPE_PORT:
                            packets.append(bytes(udp.data))
            except Exception:
                pass

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Loaded {len(packets)} NetFlow packets")
    sys.stdout.flush()
    return packets

def wait_for_next_hour():
    """Wait until the next full hour"""
    now = datetime.now()
    next_hour = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    wait_seconds = (next_hour - now).total_seconds()

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Waiting until {next_hour.strftime('%H:%M:%S')} ({wait_seconds:.0f} seconds)...")
    sys.stdout.flush()

    time.sleep(wait_seconds)

def send_packets(sock, packets):
    """Send packets spread evenly over 55 minutes"""
    num_packets = len(packets)
    delay = REPLAY_DURATION / num_packets if num_packets > 0 else 0

    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Starting replay - {num_packets} packets over {REPLAY_DURATION/60:.0f} minutes")
    print(f"  Delay between packets: {delay:.4f} seconds")
    sys.stdout.flush()

    start_time = time.time()
    sent = 0

    for payload in packets:
        updated_payload = update_netflow_v9_timestamp(payload)
        sock.sendto(updated_payload, (SYCOPE_IP, SYCOPE_PORT))
        sent += 1

        if sent % 1000 == 0:
            elapsed = time.time() - start_time
            print(f"  Sent {sent}/{num_packets} packets (elapsed: {elapsed/60:.1f} min)...")
            sys.stdout.flush()

        if delay > 0 and sent < num_packets:  # Don't wait after last packet
            time.sleep(delay)

    elapsed = time.time() - start_time
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Replay completed - sent {sent} packets in {elapsed/60:.2f} minutes")
    sys.stdout.flush()

    return sent

def main():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] NetFlow Demo Replay starting...")
    print(f"  Target: {SYCOPE_IP}:{SYCOPE_PORT}")
    print(f"  Replay duration: {REPLAY_DURATION/60:.0f} minutes per hour")
    sys.stdout.flush()

    # Load packets once at startup
    packets = load_packets()

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    loop_count = 0
    try:
        while True:
            loop_count += 1

            # Wait until next full hour
            wait_for_next_hour()

            print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] === Loop {loop_count} - Starting at hour mark ===")
            sys.stdout.flush()

            # Send packets spread over 55 minutes
            send_packets(sock, packets)

    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] Stopped by user")
    finally:
        sock.close()

if __name__ == '__main__':
    main()
