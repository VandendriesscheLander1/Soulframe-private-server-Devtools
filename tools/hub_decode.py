"""Decrypt a hub (UDP 6952) capture into the engine's plaintext packets (findings/0026, 0027).

Layers on the wire: XOR with a fixed 8-byte mask -> DTLS 1.2, PSK-AES128-GCM-SHA256 with the PSK built into the
exe, extended master secret -> NetDriver packets. The capture is a passive pktmon one (no game process touched),
so it must include the handshake.

Usage:  python tools/hub_decode.py C:\\hubcap\\hub.pcapng [--port 6952] > hub.txt
        python tools/hub_decode.py --selftest
"""
import hashlib, hmac, struct, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MASK = bytes.fromhex('638c592ce157c21b')  # .rdata 0x204B228 (findings/0026)
PSK = b'OtWrLfwVjmYmEk'
HANDSHAKE, CCS, APPDATA = 22, 20, 23


def unmask(data):
    return bytes(b ^ MASK[i % 8] for i, b in enumerate(data))


def prf(secret, label, seed, n):
    """TLS 1.2 P_SHA256."""
    out, a, seed = b'', label + seed, label + seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]


def read_pcapng(path):
    """(seconds, src ip, src port, dst ip, dst port, payload) per IPv4 UDP packet; pktmon logs a packet once per
    network component, so repeats within 10 ms are dropped."""
    data, i, out, seen = open(path, 'rb').read(), 0, [], {}
    while i < len(data):
        btype, blen = struct.unpack_from('<II', data, i)
        body = data[i + 8:i + blen - 4]
        i += blen
        if btype != 6:
            continue
        _, th, tl, cap = struct.unpack_from('<IIII', body)
        f = body[20:20 + cap][14:]  # ethernet
        if len(f) < 28 or f[0] >> 4 != 4 or f[9] != 17:
            continue
        ihl = (f[0] & 15) * 4
        sp, dp, ln = struct.unpack_from('>HHH', f, ihl)
        rec = ('.'.join(map(str, f[12:16])), sp, '.'.join(map(str, f[16:20])), dp, f[ihl + 8:ihl + ln])
        t = (th << 32 | tl) / 1e6
        if rec in seen and t - seen[rec] < 0.01:
            continue
        seen[rec] = t
        out.append((t, *rec))
    return out


def records(datagram):
    """DTLS records: (type, epoch, seq, header, fragment)."""
    i = 0
    while i + 13 <= len(datagram):
        ctype, ver, epoch, seq_hi, seq_lo, ln = struct.unpack_from('>BHHHIH', datagram, i)
        yield ctype, epoch, (seq_hi << 32) | seq_lo, datagram[i:i + 13], datagram[i + 13:i + 13 + ln]
        i += 13 + ln


class Session:
    """One DTLS connection, followed from its handshake."""

    def __init__(self):
        self.messages, self.keys, self.client_random = [], None, None

    def handshake(self, frag, from_client):
        # Only unfragmented messages are seen here (they are all small); the first ClientHello and the
        # HelloVerifyRequest don't count towards the handshake hash (RFC 6347 4.2.1).
        msg_type = frag[0]
        if msg_type == 3:
            self.messages = []
            return
        if msg_type == 1:
            self.messages = []
            self.client_random = frag[12 + 2:12 + 34]
        if msg_type == 2:
            self.server_random = frag[12 + 2:12 + 34]
        self.messages.append(frag)
        if msg_type == 16 and from_client:  # ClientKeyExchange: everything for the keys is in
            pms = struct.pack('>H', len(PSK)) + bytes(len(PSK)) + struct.pack('>H', len(PSK)) + PSK
            session_hash = hashlib.sha256(b''.join(self.messages)).digest()
            master = prf(pms, b'extended master secret', session_hash, 48)
            kb = prf(master, b'key expansion', self.server_random + self.client_random, 40)
            self.keys = {True: (AESGCM(kb[0:16]), kb[32:36]), False: (AESGCM(kb[16:32]), kb[36:40])}
            self.master = master

    def decrypt(self, header, frag, from_client):
        aead, salt = self.keys[from_client]
        explicit, sealed = frag[:8], frag[8:]
        aad = header[3:11] + header[0:3] + struct.pack('>H', len(sealed) - 16)
        return aead.decrypt(salt + explicit, sealed, aad)


def decode(packets, port=6952):
    """Yield (time, 'C>S' | 'S>C', peer, record type, plaintext) for every DTLS record to/from `port`."""
    sessions = {}
    for t, src, sp, dst, dp, payload in packets:
        if port not in (sp, dp):
            continue
        from_client = dp == port
        peer = f'{dst}:{dp}' if from_client else f'{src}:{sp}'
        s = sessions.setdefault(peer, Session())
        datagram = unmask(payload)
        if datagram[0] not in (CCS, 21, HANDSHAKE, APPDATA):  # the shutdown alert goes out unmasked (findings/0026)
            datagram = payload
        for ctype, epoch, seq, header, frag in records(datagram):
            if epoch == 0:
                if ctype == HANDSHAKE:
                    s.handshake(frag, from_client)
                yield t, 'C>S' if from_client else 'S>C', peer, ctype, frag
            elif s.keys:
                yield t, 'C>S' if from_client else 'S>C', peer, ctype, s.decrypt(header, frag, from_client)


def main(path, port=6952):
    for t, d, peer, ctype, plain in decode(read_pcapng(path), port):
        kind = {HANDSHAKE: 'hs', CCS: 'ccs', APPDATA: 'app', 21: 'alert'}.get(ctype, str(ctype))
        print(f'{t:.3f} {d} {kind:5} {len(plain):4} {plain.hex(" ")}')


def selftest():
    # RFC 5246 style check of the PRF against a known vector (from the TLS 1.2 PRF test vectors, SHA-256).
    out = prf(bytes.fromhex('9bbe436ba940f017b17652849a71db35'), b'test label',
              bytes.fromhex('a0ba9f936cda311827a6f796ffd5198c'), 100)
    assert out[:16].hex() == 'e3f229ba727be17b8d122620557cd453', out[:16].hex()
    print('selftest ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        selftest()
    else:
        main(sys.argv[1], int(sys.argv[sys.argv.index('--port') + 1]) if '--port' in sys.argv else 6952)
