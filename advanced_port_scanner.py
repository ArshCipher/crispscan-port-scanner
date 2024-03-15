#!/usr/bin/env python3

"""
CrispScan - Advanced Multithreaded Port Scanner by Arsh
Features: Port scanning, stealth and chaos modes, spoofed requests, port knocking, basic DDoS simulation, live packet graph.
"""

import socket
import threading
import argparse
import platform
import time
import logging
import json
from queue import Queue
import random
import select
from scapy.all import IP, TCP, UDP, send
import sys
import os
from colorama import init, Fore, Style
import matplotlib
from threading import Thread
import matplotlib.pyplot as plt
import numpy as np

# Configure matplotlib backend
try:
    matplotlib.use('Qt5Agg')
except ImportError:
    matplotlib.use('Agg')

# Logging and color formatting
init()
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("CrispScan")

# Shared resources
port_queue = Queue()
results = {}
packet_count = {"sent": 0, "received": 0}
lock = threading.Lock()
running = True

# ASCII art for fun terminal output
VICTORY_ART = f"""{Fore.GREEN}
   ______
  /      \\
 /________\\
 |  CRISP |
 |  SCAN  |
 |________|{Style.RESET_ALL}
"""

# Optional sound effect for scan complete
def play_sound():
    if platform.system() == "Windows":
        import winsound
        for _ in range(5):
            winsound.Beep(800, 200)
            time.sleep(0.05)
    else:
        os.system("beep -f 800 -l 200")

# Send a sequence of packets as part of a port knocking feature
def knocking_sequence(target, sequence=[12345, 54321, 1337]):
    logger.info(f"{Fore.YELLOW}Knocking sequence initiated: {sequence}{Style.RESET_ALL}")
    for port in sequence:
        packet = IP(dst=target) / UDP(dport=port)
        send(packet, verbose=0)
        packet_count["sent"] += 1
        time.sleep(0.05)

# Simulated SYN flood for testing firewalls or network behavior
def fake_ddos(target, intensity=500):
    logger.info(f"{Fore.RED}Sending totally friendly SYN flood to {target} x{intensity} times.{Style.RESET_ALL}")
    for _ in range(intensity):
        port = random.randint(1, 65535)
        packet = IP(dst=target) / TCP(dport=port, flags="S") / (b"A" * 50)
        send(packet, verbose=0)
        packet_count["sent"] += 1
        time.sleep(0.001)

# Get the banner or response string from an open socket
def grab_banner(sock, timeout=2):
    try:
        sock.settimeout(timeout)
        readable, _, _ = select.select([sock], [], [], timeout)
        if readable:
            packet_count["received"] += 1
            return sock.recv(1024).decode("utf-8", errors="ignore").strip()
    except:
        pass
    return "No banner"

# Send a simple message to open ports to provoke responses
def send_payload(sock, payload="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"):
    try:
        sock.send(payload.encode("utf-8"))
        logger.info(f"{Fore.MAGENTA}👹 sent the payload: {payload.strip()}{Style.RESET_ALL}")
    except:
        pass

# Perform spoofed TCP SYN scan using a fake source IP
def spoofed_scan(target, port, spoof_ip="192.168.1.1"):
    try:
        packet = IP(src=spoof_ip, dst=target) / TCP(dport=port, flags="S")
        send(packet, verbose=0)
        packet_count["sent"] += 1
        time.sleep(0.05)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock)
            send_payload(sock)
            results[port] = {"status": "open", "banner": banner}
            logger.info(f"{Fore.CYAN} Port {port} is open (spoofed scan) - {banner}{Style.RESET_ALL}")
        sock.close()
    except Exception as e:
        results[port] = {"status": "error", "error": str(e)}

# Main function to scan a given port with optional features
def scan_port(target, port, timeout=1, stealth=False, chaos=False, spoof=None, knock=False, ddos=None):
    if spoof:
        spoofed_scan(target, port, spoof)
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    if stealth:
        time.sleep(random.uniform(0.1, 0.5))
    if chaos:
        time.sleep(random.uniform(0, 3))

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(sock)
            send_payload(sock)
            results[port] = {"status": "open", "banner": banner}
            logger.info(f"{Fore.GREEN} Port {port} is open - {banner}{Style.RESET_ALL}")
        else:
            results[port] = {"status": "closed"}
    except Exception as e:
        results[port] = {"status": "error", "error": str(e)}
    finally:
        sock.close()

# Worker thread that takes ports from the queue and scans them
def worker(target, timeout, stealth, chaos, spoof, knock, ddos):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port, timeout, stealth, chaos, spoof, knock, ddos)
        port_queue.task_done()

# Visualize packets sent/received in real-time using matplotlib
def live_packet_viz(thread_list):
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.set_title("Packets Per Second (PPS) - ArshScan Live")
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("PPS")
    sent_line, = ax.plot([], [], label="Sent", color="red")
    recv_line, = ax.plot([], [], label="Received", color="blue")
    ax.legend()

    sent_prev = recv_prev = 0
    time_prev = t0 = time.time()
    sent_x = sent_y = recv_x = recv_y = []

    while any(t.is_alive() for t in thread_list):
        time.sleep(1)
        with lock:
            now = time.time()
            elapsed = now - time_prev
            t_rel = now - t0

            sent_now = packet_count["sent"]
            recv_now = packet_count["received"]

            sent_pps = (sent_now - sent_prev) / elapsed
            recv_pps = (recv_now - recv_prev) / elapsed

            sent_x.append(t_rel)
            sent_y.append(sent_pps)
            recv_x.append(t_rel)
            recv_y.append(recv_pps)

            sent_line.set_data(sent_x[-100:], sent_y[-100:])
            recv_line.set_data(recv_x[-100:], recv_y[-100:])
            ax.relim()
            ax.autoscale_view()

            sent_prev, recv_prev, time_prev = sent_now, recv_now, now

        plt.pause(0.01)
    time.sleep(2)
    plt.close(fig)
    logger.info(f"{Fore.YELLOW} Live visualization stopped.{Style.RESET_ALL}")

# Orchestrate the scanning process
def run_scanner(target, ports, threads=100, timeout=1, stealth=False, chaos=False, spoof=None, knock=False, ddos=None, output_file=None):
    global running
    start_time = time.time()
    logger.info(f"{Fore.YELLOW} Target acquired: {target}, scanning {len(ports)} ports...{Style.RESET_ALL}")

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        logger.error(f"{Fore.RED} Invalid hostname or IP address.{Style.RESET_ALL}")
        return

    if knock:
        knocking_sequence(target_ip)
    if ddos:
        fake_ddos(target_ip, ddos)
    if chaos:
        ports = list(ports)
        random.shuffle(ports)
        logger.info(f"{Fore.MAGENTA}🌀 Chaos mode engaged: port order randomized.{Style.RESET_ALL}")

    for port in ports:
        port_queue.put(port)

    sound_thread = Thread(target=play_sound, daemon=True)
    sound_thread.start()

    thread_list = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker, args=(target_ip, timeout, stealth, chaos, spoof, knock, ddos), daemon=True)
        t.start()
        thread_list.append(t)

    live_packet_viz(thread_list)

    for t in thread_list:
        t.join()

    elapsed = time.time() - start_time
    running = False
    logger.info(f"{Fore.GREEN} Scan complete in {elapsed:.2f} seconds.{Style.RESET_ALL}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump({"target": target_ip, "results": results}, f, indent=4)
        logger.info(f"{Fore.BLUE} Results saved to {output_file}{Style.RESET_ALL}")

    print(VICTORY_ART)
    play_sound()

# Command line interface
def main():
    parser = argparse.ArgumentParser(description="ArshScan - Advanced Port Scanner with Live Monitoring")
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 20-80)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("-to", "--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable stealth mode (random delays)")
    parser.add_argument("-c", "--chaos", action="store_true", help="Enable chaos mode (random port order)")
    parser.add_argument("--spoof", help="Spoof source IP")
    parser.add_argument("-k", "--knock", action="store_true", help="Trigger port knocking before scan")
    parser.add_argument("-d", "--ddos", type=int, help="Simulate basic SYN flood (intensity)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    try:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    except ValueError:
        logger.error(f"{Fore.RED}Invalid port range. Use format like 1-1000.{Style.RESET_ALL}")
        return

    run_scanner(args.target, ports, args.threads, args.timeout, args.stealth, args.chaos, args.spoof, args.knock, args.ddos, args.output)

if __name__ == "__main__":
    main()
