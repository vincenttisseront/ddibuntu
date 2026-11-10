#!/usr/bin/env python3
"""qemu-shot.py SOCKET SORTIE.png : capture l'écran d'une VM QEMU (moniteur sur socket Unix) puis la
convertit en PNG. Affiche « WxH couleurs pixels_non_noirs » pour permettre un contrôle automatique."""
import os
import socket
import sys
import tempfile
import time

from PIL import Image

sock_path, out_png = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sock_path)
time.sleep(0.5)
s.recv(4096)
ppm = tempfile.mktemp(suffix=".ppm")
s.sendall(("screendump %s\n" % ppm).encode())
for _ in range(50):
    time.sleep(0.2)
    if os.path.exists(ppm) and os.path.getsize(ppm) > 100:
        time.sleep(0.3)
        break
s.close()
img = Image.open(ppm).convert("RGB")
img.save(out_png)
os.unlink(ppm)
colors = img.getcolors(maxcolors=1 << 20) or []
non_black = sum(n for n, c in colors if c != (0, 0, 0))
print("%dx%d %d %d" % (img.size[0], img.size[1], len(colors), non_black))
