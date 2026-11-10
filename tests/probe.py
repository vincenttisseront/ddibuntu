#!/usr/bin/env python3
"""Sonde réseau pour les tests du pare-feu.

probe.py tcp|udp|icmp DEST PORT [SOURCE]   -> open | closed | filtered   (icmp : PORT ignoré)
listen.py équivalent : probe.py listen PORT...  (écoute TCP + écho UDP sur ces ports, jusqu'à SIGTERM)
"""
import socket
import struct
import sys
import threading


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_echo(dst, src=None, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        body = b"ddibuntu"
        head = struct.pack("!BBHHH", 8, 0, 0, 0x4242, 1)
        pkt = struct.pack("!BBHHH", 8, 0, _checksum(head + body), 0x4242, 1) + body
        s.sendto(pkt, (dst, 0))
        while True:
            data, _ = s.recvfrom(1024)
            icmp = data[(data[0] & 0x0F) * 4:]
            if icmp[0] == 0 and struct.unpack("!H", icmp[4:6])[0] == 0x4242:
                return "open"
    except socket.timeout:
        return "filtered"
    finally:
        s.close()


def probe(proto, dst, port, src=None, timeout=1.0):
    if proto == "icmp":
        return icmp_echo(dst, src, timeout)
    if proto == "tcp":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if src:
                s.bind((src, 0))
            s.connect((dst, port))
            return "open"
        except socket.timeout:
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            return "error:%s" % e
        finally:
            s.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if src:
            s.bind((src, 0))
        s.sendto(b"ping", (dst, port))
        s.recvfrom(64)
        return "open"
    except socket.timeout:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        return "error:%s" % e
    finally:
        s.close()


def listen(ports):
    def tcp_server(p):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", p))
        srv.listen(16)
        while True:
            c, _ = srv.accept()
            c.close()

    def udp_server(p):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("0.0.0.0", p))
        while True:
            data, addr = srv.recvfrom(64)
            srv.sendto(data, addr)

    for p in ports:
        threading.Thread(target=tcp_server, args=(p,), daemon=True).start()
        threading.Thread(target=udp_server, args=(p,), daemon=True).start()
    threading.Event().wait()


if __name__ == "__main__":
    if sys.argv[1] == "listen":
        listen([int(p) for p in sys.argv[2:]])
    else:
        print(probe(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4] if len(sys.argv) > 4 else None))
