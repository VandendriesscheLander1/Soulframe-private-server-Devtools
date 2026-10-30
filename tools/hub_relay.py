"""Phase 6 hub relay on UDP 6952: lets players in the same hub see each other (findings/0026, 0027).

The game runs the hub world itself (findings/0009). This server only does what DE's hub server does:
DTLS-PSK (the key built into the game), then the engine's packets with hub messages inside. It hands out ids on
join, sends everyone the others' PEER_INFO (name, account id, loadout), and passes on positions, control JSON
(emotes, trade, status) and leaves.

A joining player's loadout arrives as reliable message 8. The live client Oodle-compresses that packet, so
sf_bootstrap has to make our copy send it raw (findings/0028); until then such a player can see others, but others
won't see them.

--mirror (testing alone): each player also gets an "Echo" peer that wears their loadout and follows 2 s behind them.

Usage:  imported by tools/dummy_server.py (it serves this on its hub port)
        python tools/hub_relay.py --selftest
"""
import hashlib, hmac, json, os, socket, struct, sys, threading, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hub_decode as dtls  # MASK, prf, records, Session (key schedule shared with the decoder)
import netdriver  # seal(): the packet checksum

HANDSHAKE, CCS, APPDATA = 22, 20, 23
VERSION = b'\xfe\xfd'
SUITE = b'\x00\xa8'  # TLS_PSK_WITH_AES_128_GCM_SHA256
FRAGMENT = 1156  # reliable payload per packet, as the live server sends (findings/0027)
KEEPALIVE, TIMEOUT, RESEND = 30.0, 75.0, 0.5
MIRROR_DELAY = 2.0


def hs_msg(msg_type, msg_seq, body):
    """A DTLS handshake message, unfragmented."""
    n = len(body).to_bytes(3, 'big')
    return bytes([msg_type]) + n + struct.pack('>H', msg_seq) + b'\0\0\0' + n + body


def varint(b, i):
    v = s = 0
    while True:
        x = b[i]
        i += 1
        v |= (x & 0x7f) << s
        s += 7
        if x < 0x80:
            return v, i


def put_varint(n):
    out = b''
    while True:
        out += bytes([(n & 0x7f) | (0x80 if n > 0x7f else 0)])
        n >>= 7
        if not n:
            return out


def put_str(b):
    return put_varint(len(b)) + b


def get_str(b, i):
    n, i = varint(b, i)
    return b[i:i + n], i + n


class Player:
    """A joined player (or an Echo in --mirror mode)."""

    def __init__(self, pid, account, name, flags, channel, pos):
        self.id, self.account, self.name, self.flags, self.channel = pid, account, name, flags, channel
        self.pos = pos  # (x, y, z, yaw)
        self.loadout = None  # JSON bytes, from reliable message 8

    def peer_info(self):
        x, y, z, yaw = self.pos
        return (b'\x02' + struct.pack('<HhhhB', self.id, x, y, z, yaw) + put_str(self.name) + put_str(self.account)
                + self.flags + put_str(self.loadout) + b'\0\0\0\0')

    def position(self):
        return b'\xb4\x00' + struct.pack('<HhhhB', self.id, *self.pos)


class Conn:
    """One client: its DTLS state, the engine's reliable channel, and its hub player."""

    def __init__(self, relay, addr):
        self.relay, self.addr = relay, addr
        self.session = dtls.Session()
        self.epoch, self.seq = 0, 0  # our record numbering
        self.hs_seq = 1  # our handshake message_seq (0 was the HelloVerifyRequest)
        self.flight = []  # last handshake flight, resent when the client repeats itself
        self.open = False
        self.player = None
        self.out_seq, self.unacked = 0, {}  # reliable: seq -> (packet, last sent)
        self.in_seen, self.in_frag = set(), None
        self.last_heard = time.monotonic()

    # --- records -------------------------------------------------------------------------------------------------
    def record(self, ctype, payload):
        if self.epoch:
            aead, salt = self.session.keys[False]
            explicit = struct.pack('>HQ', self.epoch, self.seq)[:2] + struct.pack('>Q', self.seq)[2:]
            aad = explicit + bytes([ctype]) + VERSION + struct.pack('>H', len(payload))
            payload = explicit + aead.encrypt(salt + explicit, payload, aad)
        head = bytes([ctype]) + VERSION + struct.pack('>H', self.epoch) + self.seq.to_bytes(6, 'big')
        self.seq += 1
        return head + struct.pack('>H', len(payload)) + payload

    def send(self, datagram):
        self.relay.sock.sendto(dtls.unmask(datagram), self.addr)  # unmask() is its own inverse (XOR)

    def send_packet(self, *messages):
        """One engine packet: raw, checksum, header word 0x8000, one length-prefixed chunk per message."""
        body = b''.join(struct.pack('<H', len(m)) + m for m in messages)
        self.send(self.record(APPDATA, netdriver.seal(b'\0' * 5 + b'\x00\x00\x00\x80' + body)))

    # --- handshake ---------------------------------------------------------------------------------------------
    def on_handshake(self, frag, cookie_key):
        msg_type = frag[0]
        if msg_type == 1:  # ClientHello
            if self.flight:
                return [self.send(d) for d in self.flight]  # they missed our flight
            body = frag[12:]
            sid_len = body[34]
            cookie = body[35 + sid_len + 1:35 + sid_len + 1 + body[35 + sid_len]]
            want = hmac.new(cookie_key, repr(self.addr).encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(cookie, want):  # HelloVerifyRequest, stateless, as the live server does
                hvr = hs_msg(3, 0, VERSION + bytes([len(want)]) + want)
                return self.send(self.record(HANDSHAKE, hvr))
            self.session.handshake(frag, True)
            hello = VERSION + os.urandom(32) + b'\x20' + os.urandom(32) + SUITE + b'\0'
            hello += struct.pack('>H', 9) + b'\xff\x01\x00\x01\x00' + b'\x00\x17\x00\x00'  # renegotiation_info, EMS
            sh, shd = hs_msg(2, self.hs_seq, hello), hs_msg(14, self.hs_seq + 1, b'')
            self.hs_seq += 2
            self.session.handshake(sh, False)
            self.session.handshake(shd, False)
            self.flight = [self.record(HANDSHAKE, sh) + self.record(HANDSHAKE, shd)]
            self.send(self.flight[0])
        elif msg_type == 16:  # ClientKeyExchange (PSK identity): keys are ready after this
            self.session.handshake(frag, True)

    def on_finished(self, frag):
        if self.open:
            return [self.send(d) for d in self.flight]
        s = self.session
        want = dtls.prf(s.master, b'client finished', hashlib.sha256(b''.join(s.messages)).digest(), 12)
        if frag[0] != 20 or not hmac.compare_digest(frag[12:24], want):
            raise ValueError('client Finished does not verify')
        s.messages.append(frag)
        verify = dtls.prf(s.master, b'server finished', hashlib.sha256(b''.join(s.messages)).digest(), 12)
        ccs = self.record(CCS, b'\x01')
        self.epoch, self.seq = 1, 0
        fin = self.record(HANDSHAKE, hs_msg(20, self.hs_seq, verify))
        self.flight = [ccs + fin]
        self.send(self.flight[0])
        self.open = True
        self.relay.note(f'hub: {self.addr[0]}:{self.addr[1]} handshake done')

    # --- datagrams -------------------------------------------------------------------------------------------------
    def on_datagram(self, data):
        self.last_heard = time.monotonic()
        self.received = getattr(self, 'received', 0) + 1
        if self.received <= 12 and not self.open:  # what a client sends before the handshake is done, for debugging
            self.relay.note(f'hub: {self.addr[1]} #{self.received} {len(data)} B raw {data[:48].hex()} '
                            f'unmasked {dtls.unmask(data)[:48].hex()}')
        datagram = dtls.unmask(data)
        if datagram[0] not in (CCS, 21, HANDSHAKE, APPDATA):
            datagram = data  # the client's close alert is unmasked
        for ctype, epoch, seq, header, frag in dtls.records(datagram):
            if epoch == 0:
                if ctype == HANDSHAKE:
                    self.on_handshake(frag, self.relay.cookie_key)
                continue
            if not self.session.keys:
                continue
            plain = self.session.decrypt(header, frag, True)
            if ctype == HANDSHAKE:
                self.on_finished(plain)
            elif ctype == 21:
                self.relay.leave(self, 'closed')
            elif ctype == APPDATA:
                self.on_packet(plain)

    def on_packet(self, p):
        if len(p) == 8:  # NetDriver ping: answered with the same bytes (live capture)
            return self.send(self.record(APPDATA, p))
        if p[0] != 0:
            return self.relay.note(f'{self.addr}: compressed packet ({len(p)} B) dropped; is sf_bootstrap current?')
        if netdriver.checksum(p) != p[1:5]:
            return self.relay.note(f'{self.addr}: bad checksum, dropped')
        i = 9
        while i + 2 <= len(p):
            n = struct.unpack_from('<H', p, i)[0]
            self.on_message(p[i + 2:i + 2 + n])
            i += 2 + n

    def on_message(self, m):
        r = self.relay
        if m[:2] == b'\xb4\x03':  # join
            account, i = get_str(m, 2)
            x, y, z, yaw, _state = struct.unpack_from('<hhhBB', m, i)
            name, i = get_str(m, i + 8)
            flags = m[i:i + 2]
            channel, _ = get_str(m, i + 2)
            r.join(self, account, name, flags, channel, (x, y, z, yaw))
        elif not self.player:
            return
        elif m[:2] == b'\xb4\x00' and len(m) >= 9:  # position: i16 x, y, z, u8 yaw, u8 state
            self.player.pos = struct.unpack_from('<hhhB', m, 2)
            r.moved(self.player)
        elif m[:2] == b'\xb4\x04':
            r.leave(self, 'exit')
        elif m[:1] == b'\xb8':
            self.on_reliable(m)

    # --- reliable channel (b8 <u16 id> <u32 seq> <kind>) -----------------------------------------------------------
    def on_reliable(self, m):
        pid, seq, kind = struct.unpack_from('<HIB', m, 1)
        if kind == 0xc8:  # ack of ours
            self.unacked.pop(seq, None)
            return
        self.send_packet(m[:7] + b'\xc8')
        if seq in self.in_seen:
            return
        self.in_seen.add(seq)
        if kind == 0xcc:
            self.relay.on_reliable_message(self, m[8:])
        elif kind == 0x90:
            total = struct.unpack_from('<I', m, 8)[0]
            if total:
                self.in_frag = (total, bytearray(m[12:]))
            elif self.in_frag:
                self.in_frag[1].extend(m[12:])
            if self.in_frag and len(self.in_frag[1]) >= self.in_frag[0]:
                whole, self.in_frag = bytes(self.in_frag[1]), None
                self.relay.on_reliable_message(self, whole)

    def send_reliable(self, msg):
        pid = self.player.id
        parts = [b'\xcc' + msg] if len(msg) <= FRAGMENT else [
            b'\x90' + struct.pack('<I', len(msg) if o == 0 else 0) + msg[o:o + FRAGMENT] for o in range(0, len(msg), FRAGMENT)]
        for part in parts:
            self.out_seq += 1
            chunk = b'\xb8' + struct.pack('<HI', pid, self.out_seq) + part
            self.unacked[self.out_seq] = [chunk, time.monotonic()]
            self.send_packet(chunk)


class Relay:
    def __init__(self, sock, mirror=False, out=print):
        self.sock, self.mirror, self.note = sock, mirror, out
        self.cookie_key = os.urandom(32)
        self.conns, self.lock = {}, threading.RLock()
        self.next_id, self.echoes = 1, {}  # conn -> (echo Player, [(time, pos)])

    def members(self, channel, but=None):
        return [c for c in self.conns.values() if c.player and c.player.channel == channel and c is not but]

    def new_id(self):
        used = {c.player.id for c in self.conns.values() if c.player} | {e.id for e, _ in self.echoes.values()}
        while self.next_id in used or self.next_id in (0, 0xffff):
            self.next_id = (self.next_id % 0xfffe) + 1
        pid, self.next_id = self.next_id, self.next_id + 1
        return pid

    def join(self, conn, account, name, flags, channel, pos):
        if conn.player:
            return conn.send_packet(b'\xb4\x03' + struct.pack('<H', conn.player.id))  # repeated join: same answer
        conn.player = Player(self.new_id(), account, name, flags, channel, pos)
        conn.send_packet(b'\xb4\x03' + struct.pack('<H', conn.player.id))
        self.note(f'hub: {name.decode(errors="replace")} joined {channel.decode()} as {conn.player.id} from {conn.addr[0]}')
        for other in self.members(channel, but=conn):
            if other.player.loadout:
                conn.send_reliable(other.player.peer_info())

    def on_reliable_message(self, conn, msg):
        p = conn.player
        if msg[:1] == b'\x08':  # own loadout: 08 <u16 id> varint+JSON (guess: same shape as 07)
            try:
                _, i = struct.unpack_from('<H', msg, 1)[0], 3
                p.loadout, _ = get_str(msg, i)
                json.loads(p.loadout)
            except (ValueError, IndexError, struct.error) as e:
                return self.note(f'hub: loadout from {p.id} not understood ({e}): {msg[:24].hex(" ")}')
            for other in self.members(p.channel, but=conn):
                other.send_reliable(p.peer_info())
            if self.mirror:
                self.add_echo(conn)
        elif msg[:1] == b'\x07':  # control JSON (emotes, trade, status): to everyone else, with the sender's id
            relayed = b'\x07' + struct.pack('<H', p.id) + msg[3:]
            for other in self.members(p.channel, but=conn):
                other.send_reliable(relayed)
        else:
            self.note(f'hub: reliable message type {msg[0]} from {p.id} ignored')

    def moved(self, player):
        for other in self.members(player.channel):
            if other.player is not player:
                other.send_packet(player.position())
        for c, (echo, trail) in self.echoes.items():
            if c.player is player:
                trail.append((time.monotonic(), player.pos))

    def leave(self, conn, why):
        p, conn.player = conn.player, None
        self.conns.pop(conn.addr, None)
        if not p:
            return
        self.note(f'hub: {p.name.decode(errors="replace")} ({p.id}) left: {why}')
        for other in self.members(p.channel):
            other.send_reliable(b'\x04' + struct.pack('<H', p.id))
        echo = self.echoes.pop(conn, None)
        if echo:
            for other in self.members(p.channel):
                other.send_reliable(b'\x04' + struct.pack('<H', echo[0].id))

    def add_echo(self, conn):
        p = conn.player
        echo = Player(self.new_id(), b'%024x' % p.id, b'Echo\xee\x80\x80', p.flags, p.channel, p.pos)
        echo.loadout = p.loadout
        self.echoes[conn] = (echo, [])
        conn.send_reliable(echo.peer_info())

    def tick(self):
        now = time.monotonic()
        with self.lock:
            for conn in list(self.conns.values()):
                if now - conn.last_heard > TIMEOUT:
                    self.leave(conn, 'timed out')
                    continue
                if conn.player and now - getattr(conn, 'pinged', 0) > KEEPALIVE:
                    conn.pinged = now
                    conn.send_packet(b'\xb4\x05')
                for seq, entry in conn.unacked.items():
                    if now - entry[1] > RESEND:
                        entry[1] = now
                        conn.send_packet(entry[0])
            for conn, (echo, trail) in self.echoes.items():
                while trail and now - trail[0][0] >= MIRROR_DELAY:
                    echo.pos = trail.pop(0)[1]
                    conn.send_packet(echo.position())

    def handle(self, data, addr):
        with self.lock:
            conn = self.conns.get(addr)
            if conn is None:
                conn = self.conns[addr] = Conn(self, addr)
                self.note(f'hub: new connection from {addr[0]}:{addr[1]} ({len(data)} B)')
            try:
                conn.on_datagram(data)
            except Exception as e:  # one bad client must not stop the hub for everyone
                self.note(f'hub: {addr[0]}:{addr[1]} dropped ({type(e).__name__}: {e})')
                self.leave(conn, 'error')


def serve(bind, port, mirror=False, out=print):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind, port))
    relay = Relay(sock, mirror, out)

    def recv():
        while sock.fileno() != -1:  # only a closed socket ends this; anything else is noted and survived
            try:
                data, addr = sock.recvfrom(65535)
            except OSError as e:
                if getattr(e, 'winerror', 0) != 10054:  # 10054: ICMP "port unreachable" from an earlier send
                    out(f'hub: receive error {e}')
                continue
            relay.handle(data, addr)

    def ticker():
        while sock.fileno() != -1:
            time.sleep(0.1)
            try:
                relay.tick()
            except Exception as e:
                out(f'hub: tick failed ({type(e).__name__}: {e})')
    threading.Thread(target=recv, daemon=True).start()
    threading.Thread(target=ticker, daemon=True).start()
    return relay


# --- selftest: two scripted clients doing what the game does ---------------------------------------------------------
class TestClient:
    def __init__(self, port, name):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.port, self.name, self.seq, self.epoch, self.out_seq = port, name, 0, 0, 0
        self.s = dtls.Session()

    def rec(self, ctype, payload):
        if self.epoch:
            aead, salt = self.s.keys[True]
            explicit = struct.pack('>H', self.epoch) + self.seq.to_bytes(6, 'big')
            payload = explicit + aead.encrypt(salt + explicit, payload, explicit + bytes([ctype]) + VERSION + struct.pack('>H', len(payload)))
        out = bytes([ctype]) + VERSION + struct.pack('>H', self.epoch) + self.seq.to_bytes(6, 'big') + struct.pack('>H', len(payload)) + payload
        self.seq += 1
        return out

    def send(self, datagram):
        self.sock.sendto(dtls.unmask(datagram), ('127.0.0.1', self.port))

    def recv(self):
        out = []
        for ctype, epoch, seq, header, frag in dtls.records(dtls.unmask(self.sock.recvfrom(65535)[0])):
            if epoch:
                frag = self.s.decrypt(header, frag, False)
            out.append((ctype, frag))
        return out

    def connect(self):
        hello = lambda cookie: hs_msg(1, 0 if not cookie else 1, VERSION + os.urandom(32) + b'\0' + bytes([len(cookie)]) + cookie
                                      + b'\x00\x02' + SUITE + b'\x01\x00' + b'\x00\x04\x00\x17\x00\x00')
        self.send(self.rec(HANDSHAKE, hello(b'')))
        (_, hvr), = self.recv()
        ch = hello(hvr[12 + 3:])
        self.s.handshake(ch, True)
        self.send(self.rec(HANDSHAKE, ch))
        for _, m in self.recv():
            self.s.handshake(m, False)
        cke = hs_msg(16, 2, b'\x00\x08c4ad847c')
        self.s.handshake(cke, True)
        verify = dtls.prf(self.s.master, b'client finished', hashlib.sha256(b''.join(self.s.messages)).digest(), 12)
        fin = hs_msg(20, 3, verify)
        flight = self.rec(HANDSHAKE, cke) + self.rec(CCS, b'\x01')
        self.epoch, self.seq = 1, 0
        self.send(flight + self.rec(HANDSHAKE, fin))
        self.s.messages.append(fin)
        got = self.recv()
        want = dtls.prf(self.s.master, b'server finished', hashlib.sha256(b''.join(self.s.messages)).digest(), 12)
        assert got[0] == (CCS, b'\x01') and got[1][1][12:24] == want, 'server Finished does not verify'

    def packet(self, *msgs):
        body = b''.join(struct.pack('<H', len(m)) + m for m in msgs)
        self.send(self.rec(APPDATA, netdriver.seal(b'\0' * 5 + b'\x00\x00\x00\x80' + body)))

    def messages(self, until):
        """Collect hub messages (acking reliable ones) until `until(list)` is true."""
        got = []
        while not until(got):
            for ctype, p in self.recv():
                assert p[0] == 0 and netdriver.checksum(p) == p[1:5]
                i = 9
                while i + 2 <= len(p):
                    n = struct.unpack_from('<H', p, i)[0]
                    m = p[i + 2:i + 2 + n]
                    i += 2 + n
                    if m[:1] == b'\xb8' and m[7] != 0xc8:
                        self.packet(m[:7] + b'\xc8')
                        m = m[8:] if m[7] == 0xcc else m[12:]
                    got.append(m)
        return got

    def join(self):
        self.packet(b'\xb4\x03' + put_str(b'%024x' % len(self.name)) + struct.pack('<hhhBB', 1, 13123, -500, 7, 0)
                    + put_str(self.name.encode() + b'\xee\x80\x80') + b'\0\0' + put_str(b'CHAMPIONHUB_EU_EN_WIN_0') + b'\0\0')
        (ack,) = self.messages(lambda g: g)
        assert ack[:2] == b'\xb4\x03'
        self.id = struct.unpack_from('<H', ack, 2)[0]
        loadout = json.dumps({'a': {'a': f'/SF/Souls/Test/{self.name}'}}).encode()
        self.out_seq += 1
        self.packet(b'\xb8' + struct.pack('<HI', self.id, self.out_seq) + b'\xcc\x08' + struct.pack('<H', self.id) + put_str(loadout))


def selftest():
    notes = []
    relay = serve('127.0.0.1', 18952, out=notes.append)
    a, b = TestClient(18952, 'Alpha'), TestClient(18952, 'Beta')
    a.connect()
    a.join()
    assert a.messages(lambda g: any(m[:1] == b'\xb8' for m in g))  # the ack of its loadout
    b.connect()
    b.join()
    got = b.messages(lambda g: any(m[:1] == b'\x02' for m in g))  # A's PEER_INFO
    info = next(m for m in got if m[:1] == b'\x02')
    assert struct.unpack_from('<H', info, 1)[0] == a.id and b'Alpha' in info and b'/SF/Souls/Test/Alpha' in info
    got = a.messages(lambda g: any(m[:1] == b'\x02' for m in g))  # and A hears about B
    assert any(b'Beta' in m for m in got)
    a.packet(b'\xb4\x00' + struct.pack('<hhhBB', 5, 13123, -400, 9, 1))
    got = b.messages(lambda g: any(m[:2] == b'\xb4\x00' for m in g))
    assert next(m for m in got if m[:2] == b'\xb4\x00') == b'\xb4\x00' + struct.pack('<HhhhB', a.id, 5, 13123, -400, 9)
    emote = put_str(b'{"from":"x","to":"zone","msg":{"emote":"/SF/Types/Items/Emotes/DeepBow"}}')
    a.out_seq += 1
    a.packet(b'\xb8' + struct.pack('<HI', a.id, a.out_seq) + b'\xcc\x07' + struct.pack('<H', a.id) + emote)
    got = b.messages(lambda g: any(m[:1] == b'\x07' for m in g))
    assert next(m for m in got if m[:1] == b'\x07') == b'\x07' + struct.pack('<H', a.id) + emote
    a.packet(b'\xb4\x04' + struct.pack('<H', a.id))
    got = b.messages(lambda g: any(m[:1] == b'\x04' for m in g))
    assert next(m for m in got if m[:1] == b'\x04') == b'\x04' + struct.pack('<H', a.id)
    big = Player(99, b'0' * 24, b'Big', b'\0\0', b'C', (0, 0, 0, 0))
    big.loadout = json.dumps({'x': 'y' * 3000}).encode()
    assert len(big.peer_info()) > 2 * FRAGMENT  # a loadout this size goes out in three fragments
    relay.sock.close()
    print('selftest ok', notes)


if __name__ == '__main__' and sys.argv[1:] == ['--selftest']:
    selftest()
