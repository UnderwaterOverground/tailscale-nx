# Server for switch/speedtest (TCP and UDP on port 5300):
#   TCP "down <secs>\n": sends data for <secs>, then closes.
#   TCP "up\n": reads to EOF, then replies "<bytes> <secs>".
#   UDP "D <id> <kbit/s> <ms>": sends 1200-byte datagrams ('D' id seq) at that
#     rate, then "E" id <count> a few times.
#   UDP 'U' id ...: counted per id; "R <id>" replies "<count> <secs>".
import socket
import struct
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5300
DGRAM = 1200
CHUNK = b"x" * (64 << 10)


def tcp_client(c):
    with c:
        buf = b""
        while b"\n" not in buf:
            d = c.recv(64 << 10)
            if not d:
                return
            buf += d
        line, rest = buf.split(b"\n", 1)
        cmd, *args = line.split()
        if cmd == b"down":
            end = time.monotonic() + int(args[0])
            while time.monotonic() < end:
                c.sendall(CHUNK)
            print("tcp down done", flush=True)
        elif cmd == b"up":
            # Timed from the command, so data that came with it counts.
            total, first, last = len(rest), time.monotonic(), time.monotonic()
            while d := c.recv(1 << 20):
                last = time.monotonic()
                total += len(d)
            c.sendall(f"{total} {last - first:.6f}\n".encode())
            print(f"tcp up {total * 8 / max(last - first, 1e-9) / 1e6:.1f} Mbit/s", flush=True)


def tcp_server():
    s = socket.create_server(("0.0.0.0", PORT), reuse_port=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=tcp_client, args=(c,), daemon=True).start()


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
udp.bind(("0.0.0.0", PORT))
ups = {}  # id -> [count, first, last]


def blast(dst, rid, kbit, ms):
    pps = kbit * 1000 / 8 / DGRAM
    pad = b"x" * (DGRAM - 9)
    start = time.monotonic()
    end = start + ms / 1000
    seq = 0
    while (t := time.monotonic()) < end:
        due = int((t - start) * pps)
        while seq < due:
            try:
                udp.sendto(b"D" + struct.pack("<II", rid, seq) + pad, dst)
            except OSError:
                pass
            seq += 1
        time.sleep(0.0005)
    for _ in range(5):
        udp.sendto(b"E" + struct.pack("<IQ", rid, seq), dst)
        time.sleep(0.05)
    print(f"udp down {kbit // 1000} Mbit/s: sent {seq}", flush=True)


threading.Thread(target=tcp_server, daemon=True).start()
print(f"listening on {PORT}", flush=True)
while True:
    data, src = udp.recvfrom(2048)
    if data[:1] == b"U" and len(data) >= 5:
        rid = struct.unpack_from("<I", data, 1)[0]
        now = time.monotonic()
        e = ups.setdefault(rid, [0, now, now])
        e[0] += 1
        e[2] = now
    elif data[:2] == b"R ":
        e = ups.get(int(data.split()[1]), [0, 0.0, 0.0])
        udp.sendto(f"{e[0]} {e[2] - e[1]:.6f}".encode(), src)
    elif data[:2] == b"D ":
        _, rid, kbit, ms = data.split()
        threading.Thread(target=blast, args=(src, int(rid), int(kbit), int(ms)), daemon=True).start()
