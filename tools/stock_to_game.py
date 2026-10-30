"""Rewrite stock upstream Luau v6 bytecode into Soulframe Luau v6 bytecode (the mirror of luau_to_stock.py).

From soulframe-rust-workspace/research (its corpus round trip left out: this repo has no corpus).
Compile with upstream luau-compile 0.712 --binary (v6; tools/setup.ps1 downloads it to tools/luau), then:
- remaps each upstream opcode to the game's permuted byte
- booleans become tag-1 words 0/1
- string constants become tag-1 atom words where the game would use an atom:
  `a_XXXXXXXX` names always (that's how the decompiler prints unnamed atoms), method names (NAMECALL, always an
  atom in the 978 cache scripts), and other names (globals, fields, import paths) whose hash the game's scripts
  use as an atom. Values (LOADK, comparisons, table templates) stay strings.
Everything else is copied through unchanged.

    python stock_to_game.py in.luac out.luac          # one file
"""
import json, os, re, struct, sys

import luau_to_stock as L

HERE = os.path.dirname(os.path.abspath(__file__))
ATOMS_CACHE = os.path.join(HERE, '..', 'gamedata', 'corpus_atoms.json')  # made by the workspace from the game's scripts
UNNAMED = re.compile(rb'a_([0-9a-f]{8})$')
NAME_OPS = {'GETGLOBAL', 'SETGLOBAL', 'GETTABLEKS', 'SETTABLEKS'}
GAME = {L.UP.index(n): b for b, n in L.SF.items()}  # upstream opcode -> game byte


def fnv(h, b):  # name_atoms.py
    for c in b:
        h = ((h ^ c) * 0x1000193) & 0xffffffff
    return h


def fin(h):
    h ^= 0xffffffff
    return ((h << 17) | (h >> 15)) & 0xffffffff


def atom(name):
    m = UNNAMED.match(name)
    return int(m.group(1), 16) if m else fin(fnv(0x3fcb4ba3, name))


def parse(data, game):
    """Bytecode -> (strings, userdata types blob, protos, main). Each proto is a dict; constants are (tag, value)."""
    r = L.R(data)
    assert (r.u8(), r.u8()) == (6, 3), 'not Luau v6 / types v3'
    strings = [r.take(r.var()) for _ in range(r.var())]
    ud_start = r.p
    while r.u8():
        r.var()
    ud = data[ud_start:r.p]
    protos = []
    for _ in range(r.var()):
        p = {'head': r.take(5)}
        tl = r.var(); p['types'] = r.take(tl)
        n = r.var(); p['code'] = list(struct.unpack_from('<%dI' % n, r.take(4 * n)))
        k = []
        for _ in range(r.var()):
            t = r.u8()
            if t == 1: k.append((1, r.u32() if game else r.u8()))
            elif t == 0: k.append((0, None))
            elif t == 2: k.append((2, r.take(8)))
            elif t in (3, 6): k.append((t, r.var()))
            elif t == 4: k.append((4, r.u32()))
            elif t == 5: k.append((5, [r.var() for _ in range(r.var())]))
            elif t == 7: k.append((7, r.take(16)))
            else: raise ValueError('constant tag %d' % t)
        p['k'] = k
        p['children'] = [r.var() for _ in range(r.var())]
        p['line'], p['name'] = r.var(), r.var()
        li = r.u8(); p['lines'] = None
        if li:
            g = r.u8()
            p['lines'] = (g, r.take(n), r.take(4 * (((n - 1) >> g) + 1 if n else 0)))
        di = r.u8(); p['debug'] = None
        if di:
            locs = [(r.var(), r.var(), r.var(), r.u8()) for _ in range(r.var())]
            p['debug'] = (locs, [r.var() for _ in range(r.var())])
        protos.append(p)
    main = r.var()
    assert r.p == len(data), 'trailing bytes'
    return strings, ud, protos, main


def walk(code, opname):
    """(index, name, word) for each instruction."""
    i = 0
    while i < len(code):
        name = opname(code[i] & 0xff)
        yield i, name, code[i]
        i += 2 if name in L.AUX else 1


def usage(p):
    """Constant index -> set of 'method' / 'name' / 'value' uses in this proto (stock opcodes)."""
    use = {}
    add = lambda k, how: use.setdefault(k, set()).add(how)
    for i, name, w in walk(p['code'], lambda op: L.UP[op]):
        aux = p['code'][i + 1] if name in L.AUX else None
        d = w >> 16
        if name == 'NAMECALL': add(aux, 'method')
        elif name in NAME_OPS: add(aux, 'name')
        elif name == 'GETIMPORT':
            v = p['k'][d][1]
            for j in [(v >> 20) & 1023, (v >> 10) & 1023, v & 1023][:v >> 30]:
                add(j, 'name')
        elif name == 'LOADK': add(d, 'value')
        elif name == 'LOADKX': add(aux, 'value')
        elif name == 'JUMPXEQKS': add(aux & 0xffffff, 'value')
        elif name in ('ANDK', 'ORK'): add(w >> 24, 'value')
    for t, v in p['k']:
        if t == 5:
            for j in v: add(j, 'value')
    return use


def to_game(data, known):
    strings, ud, protos, main = parse(data, game=False)
    out = bytearray([6, 3]) + L.var(len(strings))
    for s in strings:
        out += L.var(len(s)) + s
    out += ud + L.var(len(protos))
    for p in protos:
        use = usage(p)
        code = list(p['code'])
        for i, name, w in walk(code, lambda op: L.UP[op]):
            if name not in L.UP or L.UP.index(name) not in GAME:
                raise ValueError('opcode %s has no game encoding' % name)
            code[i] = (w & ~0xff) | GAME[w & 0xff]
        o = bytearray(p['head']) + L.var(len(p['types'])) + p['types']
        o += L.var(len(code)) + struct.pack('<%dI' % len(code), *code)
        o += L.var(len(p['k']))
        for idx, (t, v) in enumerate(p['k']):
            how = use.get(idx, set())
            if t == 1:
                o += bytes([1]) + struct.pack('<I', v)
            elif t == 3 and how and 'value' not in how and (
                    'method' in how or UNNAMED.match(strings[v - 1]) or atom(strings[v - 1]) in known):
                o += bytes([1]) + struct.pack('<I', atom(strings[v - 1]))
            elif t == 0: o.append(0)
            elif t in (2, 7): o += bytes([t]) + v
            elif t in (3, 6): o += bytes([t]) + L.var(v)
            elif t == 4: o += bytes([4]) + struct.pack('<I', v)
            elif t == 5: o += bytes([5]) + L.var(len(v)) + b''.join(map(L.var, v))
        o += L.var(len(p['children'])) + b''.join(map(L.var, p['children']))
        o += L.var(p['line']) + L.var(p['name'])
        if p['lines']:
            g, offs, abs_ = p['lines']
            o += bytes([1, g]) + offs + abs_
        else:
            o.append(0)
        if p['debug']:
            locs, ups = p['debug']
            o += bytes([1]) + L.var(len(locs))
            for a, b, c, reg in locs:
                o += L.var(a) + L.var(b) + L.var(c) + bytes([reg])
            o += L.var(len(ups)) + b''.join(map(L.var, ups))
        else:
            o.append(0)
        out += o
    return bytes(out + L.var(main))


def known_atoms():
    """Every atom word the game's own scripts use as a name (gamedata/corpus_atoms.json)."""
    return set(json.load(open(ATOMS_CACHE)))


if __name__ == '__main__':
    src, dst = sys.argv[1:3]
    open(dst, 'wb').write(to_game(open(src, 'rb').read(), known_atoms()))
