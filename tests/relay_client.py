#!/usr/bin/env python3
"""Agent de relais DHCP de test (giaddr) : relay_client.py ADRESSE_RELAIS MAC SERVEUR[,SERVEUR...] [--discover-only] [--secs=N]
Envoie un DISCOVER à chaque serveur, prend la première réponse, puis un REQUEST au serveur qui a répondu.
Sortie JSON : {"server": ip du serveur qui a répondu, "offer": ip proposée, "ack": ip confirmée | null}. Aucun client réel : sert aux essais de bail Kea HA sur la boucle locale."""
import json, random, socket, struct, sys, time

RELAY, MAC, SERVERS = sys.argv[1], sys.argv[2], sys.argv[3].split(',')
SECS = next((int(a.split('=')[1]) for a in sys.argv if a.startswith('--secs=')), 0)   # « secs » : temps écoulé annoncé par le client ; sert au HA à compter les clients sans réponse
mac = bytes(int(x, 16) for x in MAC.split(':'))
MAGIC = b'\x63\x82\x53\x63'

def packet(xid, mtype, requested=None, server=None):
    p = struct.pack('!BBBBIHH4s4s4s4s', 1, 1, 6, 1, xid, SECS, 0x8000, b'\0' * 4, b'\0' * 4, b'\0' * 4, socket.inet_aton(RELAY))
    p += mac + b'\0' * 10 + b'\0' * 64 + b'\0' * 128 + MAGIC
    o = bytes([53, 1, mtype]) + bytes([61, 7, 1]) + mac
    if requested: o += bytes([50, 4]) + socket.inet_aton(requested)
    if server: o += bytes([54, 4]) + socket.inet_aton(server)
    return p + o + bytes([55, 3, 1, 3, 51]) + b'\xff'

def parse(data, xid):
    if len(data) < 240 or data[0] != 2 or struct.unpack('!I', data[4:8])[0] != xid or data[236:240] != MAGIC: return None
    out = {'yiaddr': socket.inet_ntoa(data[16:20])}
    i = 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0: i += 1; continue
        code, ln = data[i], data[i + 1]; v = data[i + 2:i + 2 + ln]; i += 2 + ln
        if code == 53: out['type'] = v[0]
        elif code == 54: out['sid'] = socket.inet_ntoa(v)
    return out

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((RELAY, 67)); s.settimeout(1)

def exchange(targets, mtype, expect, **kw):
    xid = random.getrandbits(32)
    for _ in range(3):
        for t in targets: s.sendto(packet(xid, mtype, **kw), (t, 67))
        end = time.time() + 2
        while time.time() < end:
            try: data, src = s.recvfrom(2048)
            except socket.timeout: break
            r = parse(data, xid)
            if r and r.get('type') == expect: r['src'] = src[0]; return r
    return None

res = {'server': None, 'offer': None, 'ack': None}
o = exchange(SERVERS, 1, 2)
if o:
    res['server'], res['offer'] = o['src'], o['yiaddr']
    if '--discover-only' not in sys.argv:
        a = exchange([o['src']], 3, 5, requested=o['yiaddr'], server=o['sid'])
        if a: res['ack'] = a['yiaddr']
print(json.dumps(res))
