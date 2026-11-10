#!/usr/bin/env python3
"""Client DHCP de test : dhcp_client.py INTERFACE MAC  ->  JSON {offer: {...}, ack: {...}}  (échange réel sur le réseau)."""
import json, os, random, socket, struct, sys, time

IFACE, MAC = sys.argv[1], sys.argv[2]
mac = bytes(int(x, 16) for x in MAC.split(':'))
MAGIC = b'\x63\x82\x53\x63'

def packet(xid, mtype, requested=None, server=None):
    p = struct.pack('!BBBBIHH4s4s4s4s', 1, 1, 6, 0, xid, 0, 0x8000, b'\0' * 4, b'\0' * 4, b'\0' * 4, b'\0' * 4)
    p += mac + b'\0' * 10 + b'\0' * 64 + b'\0' * 128 + MAGIC
    o = bytes([53, 1, mtype])
    if requested: o += bytes([50, 4]) + socket.inet_aton(requested)
    if server: o += bytes([54, 4]) + socket.inet_aton(server)
    o += bytes([55, 6, 1, 3, 6, 15, 51, 54]) + b'\xff'
    return p + o

def parse(data, xid):
    if len(data) < 240 or data[0] != 2 or struct.unpack('!I', data[4:8])[0] != xid or data[236:240] != MAGIC: return None
    out = {'yiaddr': socket.inet_ntoa(data[16:20]), 'chaddr': ':'.join('%02x' % b for b in data[28:34])}
    i = 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0: i += 1; continue
        code, ln = data[i], data[i + 1]; v = data[i + 2:i + 2 + ln]; i += 2 + ln
        if code == 53: out['type'] = v[0]
        elif code == 54: out['server'] = socket.inet_ntoa(v)
        elif code == 3: out['routers'] = [socket.inet_ntoa(v[k:k + 4]) for k in range(0, ln, 4)]
        elif code == 6: out['dns'] = [socket.inet_ntoa(v[k:k + 4]) for k in range(0, ln, 4)]
        elif code == 15: out['domain'] = v.decode()
        elif code == 51: out['lease'] = struct.unpack('!I', v)[0]
    return out

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, 25, IFACE.encode())      # SO_BINDTODEVICE
s.bind(('0.0.0.0', 68)); s.settimeout(3)

def exchange(mtype, expect, **kw):
    xid = random.getrandbits(32)
    for _ in range(4):
        s.sendto(packet(xid, mtype, **kw), ('255.255.255.255', 67))
        end = time.time() + 3
        while time.time() < end:
            try: data, _ = s.recvfrom(2048)
            except socket.timeout: break
            r = parse(data, xid)
            if r and r.get('type') == expect: return r
    return None

offer = exchange(1, 2)
res = {'offer': offer, 'ack': None}
if offer and '--no-request' not in sys.argv:
    res['ack'] = exchange(3, 5, requested=offer['yiaddr'], server=offer['server'])
print(json.dumps(res))
