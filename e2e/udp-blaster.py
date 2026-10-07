# UDP stream source for memory tests (runs in the peer's network namespace):
# "go <count> <pps>" sends <count> 1200-byte datagrams back to the sender.
import socket
import sys
import threading
import time

port = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
payload = b"x" * 1200


def blast(dst, count, pps):
    start = time.monotonic()
    for i in range(count):
        s.sendto(payload, dst)
        ahead = start + (i + 1) / pps - time.monotonic()
        if ahead > 0:
            time.sleep(ahead)


while True:
    data, src = s.recvfrom(64)
    parts = data.split()
    if len(parts) == 3 and parts[0] == b"go":
        threading.Thread(target=blast, args=(src, int(parts[1]), int(parts[2])), daemon=True).start()
