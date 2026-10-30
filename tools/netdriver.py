"""Soulframe NetDriver UDP packet checksum (build P16H6, findings/0026 "Checksum (resolved)").

Record layout (DTLS plaintext): [0]=0x00 (raw, no Oodle) | [1:5] checksum | [5:] header+chunks.
checksum = big-endian crc32c(SALT, seed=crc32c(record[5:])), i.e. bswap of the u32 CRC.
Send 0x80672B..0x80675D, verify 0x121BE91..0x121BEB8; crc32c (hw) 0x18E0FD0 via thunk 0x6D05C0.
"""
import sys

# .rdata 0x204B300: 33 bytes, the trailing 'I' is part of the string (copied by 0x323D0).
SALT = b'b471e49539930dc9b5a131e6247c7387I'

_T = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0x82F63B78 if _c & 1 else 0)
    _T.append(_c)


def crc32c(data: bytes, seed: int = 0) -> int:
    c = seed ^ 0xFFFFFFFF
    for b in data:
        c = _T[(c ^ b) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


def checksum(packet: bytes, salt: bytes = SALT) -> bytes:
    """The 4 bytes at packet[1:5]. Only for header word 0x8000 (bit15, id 0), which is all the hub uses;
    other packets use the per-connection salt SALT + bytes([request]) (0x121BF35)."""
    return crc32c(salt, crc32c(packet[5:])).to_bytes(4, 'big')


def seal(packet: bytes) -> bytes:
    """Fill in [1:5] of a raw (0x00-prefixed) record."""
    return packet[:1] + checksum(packet) + packet[5:]


if __name__ == '__main__' and '--selftest' in sys.argv:
    assert crc32c(b'123456789') == 0xE3069283
    assert checksum(bytes.fromhex('00db1d3f600000008004 00b4035100'.replace(' ', ''))) == bytes.fromhex('db1d3f60')
    n = {}
    try:
        lines = open(r'C:\hubcap\hub.txt').read().splitlines()
    except OSError:
        lines = []
    for line in lines:
        p = line.split()
        if len(p) < 5 or p[2] != 'app' or p[3] == '8':
            continue
        rec = bytes.fromhex(''.join(p[4:]))
        if rec[0] != 0:  # Oodle-compressed: CRC is over the decompressed buffer
            continue
        assert checksum(rec) == rec[1:5], line[:40]
        n[p[1]] = n.get(p[1], 0) + 1
    print('selftest ok, matched', n)
