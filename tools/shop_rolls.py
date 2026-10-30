"""The native weapon temper roll (ShopsDecode.md): the part of soulframe-rust-workspace/research/shop_rolls.py the
server uses. admin.py sets P to the package data (vendor.packages()) before the first call.

Usage:  python tools/shop_rolls.py      checks against data-independent vectors
"""
import struct
from collections import Counter

MASK = (1 << 64) - 1
MULT, INC = 0x5851F42D4C957F2D, 0x14057B7EF767814F
RARITY = {"COMMON": 0, "UNCOMMON": 1, "RARE": 2, "LEGENDARY": 3}
MASSES = [struct.unpack("<f", bytes.fromhex(h))[0] for h in ("ae47413f", "ae47613e", "0ad7a33c", "0ad7a33b")]
FLT_MIN = struct.unpack("<f", bytes.fromhex("00008000"))[0]
POWER_SCALE = struct.unpack("<d", bytes.fromhex("000040000000103e"))[0]   # nearest double to 1/(2^30-1)
COUNT_RANGE = {1: (0, 1), 2: (1, 3), 3: (2, 4), 4: (3, 5), 5: (4, 6), 6: (5, 8)}

P = None


def f32(x): return struct.unpack("<f", struct.pack("<f", x))[0]


def step(s): return (s * MULT + INC) & MASK


def attr(path, key):
    while path:
        pkg = P.get(path)
        if not pkg: return None
        if key in pkg["attributes"]: return pkg["attributes"][key]
        path = pkg.get("parent")


def weights(rarities):
    """Native bucket weights: f32 per-row mass/bucket, sequential f32 sum, one f32 reciprocal."""
    c = Counter(rarities)
    raw = {r: max(f32(MASSES[r] / n), FLT_MIN) for r, n in c.items()}
    tot = 0.0
    for r in rarities: tot = f32(tot + raw[r])
    inv = f32(1.0 / tot)
    return [f32(raw[r] * inv) for r in rarities]


def pick(ws, u24):
    """Inclusive subtractive walk; falls back to the last row."""
    rem = u24 / (1 << 24)
    for i, w in enumerate(ws):
        if rem <= w: return i
        rem -= w
    return len(ws) - 1


def roll_tempers(manifest, quality, state):
    entries = attr(manifest, "UpgradeEntries") or []
    cands = [e for e in entries if e.get("CanBeBuff")]
    if not cands: return []
    lo, hi = COUNT_RANGE[quality]
    counts = list(range(lo, hi + 1))
    state = step(state)
    n = counts[pick(weights([0] * len(counts)), (state >> 38) & 0xFFFFFF)]
    out, seen = [], set()
    ws = weights([RARITY[e["Rarity"]] for e in cands])
    for _ in range(n):
        if not cands: break
        state = step(state)
        i = pick(ws, (state >> 38) & 0xFFFFFF)
        e = cands[i]
        if not e.get("CanRollTwice") or e["Tag"] in seen:
            cands.pop(i); ws = weights([RARITY[x["Rarity"]] for x in cands])
        state = step(state)                              # power draw, interleaved
        power = min(max(f32(((state >> 32) & 0x3FFFFFFF) * POWER_SCALE), 0.0), 1.0)
        out.append((e, int(power * 1073741823.0)))
        seen.add(e["Tag"])
    return out


if __name__ == "__main__":
    s = 0
    for _ in range(6): s = step(s)
    assert s == 0x8f947f36d0d0f606
    assert weights([0, 0]) == [0.5, 0.5] and pick([0.5, 0.5], 1 << 23) == 0  # inclusive <=
    print("checks ok")
