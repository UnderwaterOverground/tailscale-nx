#!/usr/bin/env python3
"""TCP + UDP echo on one port (default 7), on all interfaces: the peer side of
the vsock/MITM test suite when the Mac is the tailnet peer."""
import socket, sys, threading

port = int(sys.argv[1]) if len(sys.argv) > 1 else 7

def tcp_client(c):
    with c:
        while (d := c.recv(65536)):
            c.sendall(d)

def tcp():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        c, a = s.accept()
        print("tcp", a, flush=True)
        threading.Thread(target=tcp_client, args=(c,), daemon=True).start()

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(65536)
        print("udp", a, len(d), flush=True)
        s.sendto(d, a)

threading.Thread(target=tcp, daemon=True).start()
print(f"echo on tcp+udp :{port}", flush=True)
udp()
