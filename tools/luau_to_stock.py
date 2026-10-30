"""The Luau v6 bytecode pieces stock_to_game.py needs, from soulframe-rust-workspace/research/luau_to_stock.py (which
also converts the other way, game -> stock, over a corpus this repo doesn't have).
"""
import json, struct, os

# Encoded byte -> upstream opcode name, from soulframe-reversing/opcode-map.json.
# SOULFRAME_OPCODE_MAP overrides the path (e.g. to try a proposed map).
MAP_PATH = os.environ.get('SOULFRAME_OPCODE_MAP') or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'gamedata', 'opcode-map.json')
SF = {int(b, 16): n for b, n in json.load(open(MAP_PATH))['opcodes'].items()}
UP = 'NOP BREAK LOADNIL LOADB LOADN LOADK MOVE GETGLOBAL SETGLOBAL GETUPVAL SETUPVAL CLOSEUPVALS GETIMPORT GETTABLE SETTABLE GETTABLEKS SETTABLEKS GETTABLEN SETTABLEN NEWCLOSURE NAMECALL CALL RETURN JUMP JUMPBACK JUMPIF JUMPIFNOT JUMPIFEQ JUMPIFLE JUMPIFLT JUMPIFNOTEQ JUMPIFNOTLE JUMPIFNOTLT ADD SUB MUL DIV MOD POW ADDK SUBK MULK DIVK MODK POWK AND OR ANDK ORK CONCAT NOT MINUS LENGTH NEWTABLE DUPTABLE SETLIST FORNPREP FORNLOOP FORGLOOP FORGPREP_INEXT FASTCALL3 FORGPREP_NEXT NATIVECALL GETVARARGS DUPCLOSURE PREPVARARGS LOADKX JUMPX FASTCALL COVERAGE CAPTURE SUBRK DIVRK FASTCALL1 FASTCALL2 FASTCALL2K FORGPREP JUMPXEQKNIL JUMPXEQKB JUMPXEQKN JUMPXEQKS IDIV IDIVK'.split()
AUX = {'GETGLOBAL','SETGLOBAL','GETIMPORT','GETTABLEKS','SETTABLEKS','NAMECALL','JUMPIFEQ','JUMPIFLE','JUMPIFLT','JUMPIFNOTEQ','JUMPIFNOTLE','JUMPIFNOTLT','NEWTABLE','SETLIST','FORGLOOP','LOADKX','FASTCALL2','FASTCALL2K','FASTCALL3','JUMPXEQKNIL','JUMPXEQKB','JUMPXEQKN','JUMPXEQKS'}


class R:
    def __init__(s, b): s.b, s.p = b, 0
    def u8(s): s.p += 1; return s.b[s.p - 1]
    def u32(s): v = struct.unpack_from('<I', s.b, s.p)[0]; s.p += 4; return v
    def take(s, n): v = s.b[s.p:s.p + n]; s.p += n; return v
    def var(s):
        v = sh = 0
        while True:
            c = s.u8(); v |= (c & 0x7f) << sh; sh += 7
            if not c & 0x80: return v


def var(v):
    out = bytearray()
    while True:
        c = v & 0x7f; v >>= 7
        if v: out.append(c | 0x80)
        else: out.append(c); return bytes(out)


