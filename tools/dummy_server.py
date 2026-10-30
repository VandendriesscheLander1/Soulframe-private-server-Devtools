"""Phase 2/3 dummy server: answer *.soulframe.com on 127.0.0.1:80 and :443, log everything.

Serves the cache manifest index (fixtures/origin/H.Cache.bin, same bytes for the whole
build, see findings/0011), inventory.php from the saved inventory (see tools/admin.py), and any .../<name>[.php] from fixtures/<name>/response.json or
response.raw when that exists (Phase 3 replay, see tools/fixtures_from_capture.py). Everything else gets a 404. Each request becomes one line on stdout plus one JSON line in
captures/dummy/<start time>/requests.jsonl, with request bodies saved next to it.

Phase 6: login.php logs in per email (tools/admin.py accounts), and every call with ?accountId=&nonce= works on
that account's inventory; a pair that doesn't match the latest login gets a 403. The login answer and hub.php point
IRC/NRS/hub at the address the client reached us on, so other players need nothing but our address. UDP 4950 (NRS)
is only logged, and so is UDP 6952 unless --hub is given.

UNFINISHED, OFF BY DEFAULT: the hub relay (tools/hub_relay.py, findings/0027) that shows other players in enclaves
(Kith of Kings). It was never confirmed in a box run and is parked for now. Without it the enclaves work as solo.

Usage:  python tools/dummy_server.py                  (this PC only; makes certs/ on first run)
        python tools/dummy_server.py --host           (also other PCs: LAN, Tailscale/ZeroTier)
        python tools/dummy_server.py --hub            (unfinished: enclave hub relay, other players in enclaves)
        python tools/dummy_server.py --mirror         (implies --hub: an "Echo" of yourself, to test the hub alone)
        python tools/dummy_server.py --selftest       (high ports, checks HTTP + TLS + chunked)
"""
import datetime, gzip, hashlib, http.client, http.server, ipaddress, json, os, pathlib, re, socket, ssl, sys, threading, urllib.parse
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import admin  # tools/admin.py: saved inventory + request handlers
import vendor  # tools/vendor.py: getVendorInfo from the vendor manifest (Phase 5)
import hub_relay  # tools/hub_relay.py: UDP hub relay (Phase 6)

ROOT = pathlib.Path(__file__).resolve().parent.parent
CERT, KEY = ROOT / 'certs/soulframe.crt', ROOT / 'certs/soulframe.key'  # leaf + CA chain
CA = ROOT / 'certs/ca.crt'
MANIFEST = ROOT / 'fixtures/origin/H.Cache.bin'
OUT = ROOT / 'captures/dummy' / datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
lock, state_lock, counter = threading.Lock(), threading.Lock(), [0]
BIND = '127.0.0.1'  # --host: 0.0.0.0
HUB_PORT, NRS_PORT = 6952, 4950
# EZIP (findings/0017): 0x0a | RSA-1024(key+iv) | 4 B nonce | 4 B checksum | AES-192-CBC(gzip(body)).
# sf_bootstrap makes the key and iv all zeros in the box, so we skip the RSA part.
EZIP_HEADER, EZIP_KEY, EZIP_IV = 1 + 128 + 4 + 4, bytes(24), bytes(16)


def ezip_decode(body: bytes) -> bytes:
    dec = Cipher(algorithms.AES(EZIP_KEY), modes.CBC(EZIP_IV)).decryptor()
    unpad = padding.PKCS7(128).unpadder()
    data = unpad.update(dec.update(body[EZIP_HEADER:]) + dec.finalize()) + unpad.finalize()
    return gzip.decompress(data)


def ezip_encode(plain: bytes) -> bytes:  # for the selftest only
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(EZIP_KEY), modes.CBC(EZIP_IV)).encryptor()
    data = pad.update(gzip.compress(plain, 9)) + pad.finalize()
    return b'\x0a' + bytes(EZIP_HEADER - 1) + enc.update(data) + enc.finalize()


def log(**rec):
    rec = {'at': datetime.datetime.now().isoformat(timespec='milliseconds'), **rec}
    with lock:
        OUT.mkdir(parents=True, exist_ok=True)
        with open(OUT / 'requests.jsonl', 'a') as f:
            f.write(json.dumps(rec) + '\n')
    return rec


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'  # keep-alive, like the real servers

    def read_body(self):
        if 'chunked' in self.headers.get('Transfer-Encoding', '').lower():
            body = b''
            while size := int(self.rfile.readline().split(b';')[0], 16):
                body += self.rfile.read(size)
                self.rfile.readline()
            while self.rfile.readline() not in (b'\r\n', b'\n', b''):  # trailers
                pass
            return body
        return self.rfile.read(int(self.headers.get('Content-Length') or 0))

    def handle_any(self):
        body = self.read_body()
        if self.headers.get('Content-Encoding', '').lower() == 'ezip':
            try:
                body = ezip_decode(body)
            except (ValueError, OSError) as e:  # bad padding or gzip: a real random key (bootstrap hook missing), keep raw
                print(f'  !!  EZIP body not readable ({e}); is sf_bootstrap.dll current?', flush=True)
        with lock:
            counter[0] += 1
            n = counter[0]
        path, _, query = self.path.partition('?')
        name = path.rsplit('/', 1)[-1].removesuffix('.php')
        if not re.fullmatch(r'[A-Za-z0-9_]+', name):  # it becomes a file name below; '..\x', 'C:\x' would escape
            name = '_'
        q = dict(urllib.parse.parse_qsl(query))
        here = self.connection.getsockname()[0]  # the address this client reached us on; our UDP services are there too

        body_file = None
        if body:
            OUT.mkdir(parents=True, exist_ok=True)
            body_file = f'{n:05d}_request.bin'
            kept = body
            if name == 'login':  # never keep a player's password (hash) on disk
                try:
                    kept = json.dumps(json.loads(body) | {'password': '<not kept>'}).encode()
                except (ValueError, TypeError):
                    kept = b'<login body not kept>'
            (OUT / body_file).write_bytes(kept)

        canned = ROOT / 'fixtures' / name
        # Phase 4 state (tools/admin.py), wins over the fixture. Only the inventory: data/ also holds accounts.json.
        saved = admin.INV if name == 'inventory' else None
        answer = failed = denied = acct = inv_path = None
        if 'accountId' not in q or 'nonce' not in q:
            # Before accounts existed every call used data/inventory.json; once there are accounts, inventory changes
            # need one (the hub call has accountId but no nonce, and doesn't touch the inventory).
            if (name in admin.HANDLERS or name in ('inventory', 'credits')) and admin.accounts():
                denied = True
                print(f'  !!  {name}: no accountId/nonce', flush=True)
        else:  # every API call after login (findings/0007)
            with state_lock:
                acct = admin.session(q['accountId'], q['nonce'])
                if acct and name == 'inventory':
                    admin.load(inv_path := admin.inventory_path(acct))  # a new player's inventory starts from the seed
            if acct is None:  # ponytail: DE's answer for a stale nonce is unknown; a 403 makes the client log in again
                denied = True
                print(f'  !!  {name}: accountId/nonce of no current login', flush=True)
            else:
                inv_path = admin.inventory_path(acct)
                saved = inv_path if name == 'inventory' else saved
        if name == 'devCheats' and not ipaddress.ip_address(self.client_address[0]).is_loopback:
            denied = True  # the F9 panel's item cheats: only the player at this PC, never others on a shared host
            print(f'  !!  devCheats from {self.client_address[0]} refused (this PC only)', flush=True)
        login = None
        if self.command == 'POST' and name == 'login':
            try:
                creds = json.loads(body)
                with state_lock:
                    login = admin.login(str(creds['email']), str(creds['password']))
            except (ValueError, KeyError, TypeError) as e:  # EZIP not readable (old sf_bootstrap) or not a login body
                print(f'  !!  login body not readable ({type(e).__name__})', flush=True)
            if login is None:
                denied = True
                print('  !!  login refused (wrong password for that email, or no email)', flush=True)
            else:
                print(f'  ->  {login["email"]} logged in as {login["id"]}', flush=True)
        if self.command == 'POST' and name in admin.HANDLERS and not denied:  # Phase 4: apply it to the saved inventory
            try:
                with state_lock:
                    inv = admin.load(inv_path)
                    # URL flags reach the handler as _query (claimCompletedRecipe's &rush=1)
                    answer = admin.HANDLERS[name](inv, json.loads(body) | {'_query': q})
                    admin.save(inv, inv_path)
                answer = {} if answer is None else answer  # applied: never fall through to a 404
            except (ValueError, KeyError, TypeError) as e:  # bad/unknown body: don't save, and say it failed
                # Not the fixture: its answer is the live account's (box run 20261029T190809 got the live startRecipe
                # RecipeId, which the client then tried to claim). ponytail: DE's error answer is unknown; a 500 shows
                # the client's own "failed" message.
                failed = True
                print(f'  !!  {name}: not applied ({type(e).__name__}: {e})', flush=True)
        # Phase 3 replay: the captured answer as-is (the real servers send everything as text/html).
        if path.endswith('/H.Cache.bin!E_---------------------w') and MANIFEST.exists():
            status, out, ctype = 200, MANIFEST.read_bytes(), 'application/octet-stream'
        elif denied:
            status, out, ctype = 403, b'', 'text/html; charset=UTF-8'
        elif name == 'hub':  # arbiter /api/hub: our UDP hub relay (findings/0009)
            status, out, ctype = 200, json.dumps(f'hub {here}:{HUB_PORT}').encode(), 'text/html; charset=UTF-8'
        elif failed:
            status, out, ctype = 500, b'', 'text/html; charset=UTF-8'
        elif answer is not None:  # {} = handled with no answer: an empty body, as the real server sends
            status, out, ctype = 200, json.dumps(answer).encode() if answer else b'', 'text/html; charset=UTF-8'
        elif name == 'getVendorInfo' and (vtype := urllib.parse.parse_qs(query).get('vendor', [''])[0]) in vendor.KNOWN:
            status, out, ctype = 200, json.dumps(vendor.vendor_info(vtype)).encode(), 'text/html; charset=UTF-8'
        elif name == 'credits':  # the wallet in the top bar: the fixture's shape, the saved inventory's amounts
            doc = json.loads((canned / 'response.raw').read_text(encoding='utf-8'))
            with state_lock:
                inv = admin.load(inv_path)
            doc |= {k: inv[k] for k in doc if k in inv}
            status, out, ctype = 200, json.dumps(doc).encode(), 'text/html; charset=UTF-8'
        elif saved and saved.exists():
            status, out, ctype = 200, saved.read_bytes(), 'text/html; charset=UTF-8'
        elif (canned / 'response.json').exists():  # hand-edited JSON
            doc = json.loads((canned / 'response.json').read_text(encoding='utf-8'))
            if isinstance(doc, dict) and 'ClientType' in doc:  # login: echo the client's ct (live STM, the box MSI)
                doc['ClientType'] = q.get('ct', doc['ClientType'])
            if login:  # this player's identity; chat and NRS relays on this server (findings/0007)
                doc |= {k: login[k] for k in ('id', 'Nonce', 'DisplayName', 'Token')} | {'IRC': [here], 'NRS': [here]}
            status, out, ctype = 200, json.dumps(doc).encode(), 'text/html; charset=UTF-8'
        elif (canned / 'response.raw').exists():  # from tools/fixtures_from_capture.py
            status, out, ctype = 200, (canned / 'response.raw').read_bytes(), 'text/html; charset=UTF-8'
        else:
            status, out, ctype = 404, b'', 'text/html; charset=UTF-8'

        scheme = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
        log(n=n, scheme=scheme, sni=getattr(self.connection, 'sni', None), method=self.command,
            host=self.headers.get('Host'), path=self.path, headers=dict(self.headers),
            body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest() if body else None,
            body_file=body_file, status=status, response_bytes=len(out))
        print(f'{n:5d} {status} {scheme:5} {self.command:4} {self.headers.get("Host")}{self.path}'
              f'  [{len(body)} B in, {len(out)} B out]', flush=True)

        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_HEAD = do_DELETE = do_OPTIONS = handle_any
    requests_seen = 0

    def handle(self):
        super().handle()
        if not self.requests_seen:
            # Schannel (WinHTTP) closes without an alert when it rejects our cert, so this is
            # the only trace of a trust failure.
            rec = log(event='closed_without_request', sni=getattr(self.connection, 'sni', None),
                      tls=isinstance(self.connection, ssl.SSLSocket))
            print(f'  !!  connection closed without a request (tls={rec["tls"]}, sni={rec["sni"]})'
                  ' - client rejected our cert?', flush=True)

    def send_response(self, *a, **kw):
        self.requests_seen += 1
        super().send_response(*a, **kw)

    def log_message(self, *a):  # we print our own line
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # TLS handshake errors land here: a client that rejects our cert shows up as an alert.
        err = sys.exc_info()[1]
        rec = log(event='error', client=client_address[1], sni=getattr(request, 'sni', None),
                  error=f'{type(err).__name__}: {err}')
        print(f'  !!  {rec["error"]}  (sni={rec["sni"]})', flush=True)


def serve_udp(port):
    """Log what clients send to the NRS relay / hub ports. ponytail: no answers yet, the transport is still being
    worked out (findings/0026); the hub then just shows no other players, as before."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND, port))
    def run():
        seen, logged = set(), 0
        while True:
            try:
                data, peer = sock.recvfrom(65535)
            except OSError as e:
                if getattr(e, 'winerror', 0) == 10054:  # an ICMP "port unreachable" for an earlier send; keep going
                    continue
                return  # socket closed
            logged += 1
            if logged > 200_000:  # ponytail: logging only; a flood stops being logged rather than filling the disk
                continue
            log(event='udp', port=port, peer=f'{peer[0]}:{peer[1]}', bytes=len(data), hex=data.hex())
            if (peer, port) not in seen and len(seen) < 1000:
                seen.add((peer, port))
                print(f'      udp :{port} first packet from {peer[0]}:{peer[1]} ({len(data)} B)', flush=True)
    threading.Thread(target=run, daemon=True).start()
    return sock


def make_certs():
    """First run: a local CA and a *.soulframe.com leaf signed by it. sf_bootstrap turns the game's TLS checks off,
    so these only have to exist; the CA key is never written."""
    if CERT.exists() and KEY.exists():
        return
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    def cert(name, key, issuer, issuer_key, days, ca):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(key.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
        if ca:
            b = b.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                              data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                              crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        else:
            b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName('*.soulframe.com'), x509.DNSName('soulframe.com')]), critical=False)
        return b.sign(issuer_key, hashes.SHA256())
    ca_name = 'soulframe private server local CA'
    ca_key, leaf_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    ca = cert(ca_name, ca_key, ca_name, ca_key, 3650, True)
    leaf = cert('*.soulframe.com', leaf_key, ca_name, ca_key, 825, False)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    CERT.parent.mkdir(exist_ok=True)
    KEY.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    CERT.write_bytes(pem(leaf) + pem(ca))
    CA.write_bytes(pem(ca))
    print(f'made new certificates in {CERT.parent}', flush=True)


def serve(port, tls):
    srv = Server((BIND, port), Handler)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        def on_sni(sock, name, _ctx):
            sock.sni = name  # remembered so the log shows which hostname the client asked for
        ctx.sni_callback = on_sni
        # Handshake in the handler thread, so one stuck client can't block accept().
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def selftest():
    import tempfile
    tmp = pathlib.Path(tempfile.mkdtemp())
    admin.INV, admin.ACCOUNTS = tmp / 'inventory.json', tmp / 'accounts.json'  # never the real accounts
    serve(18080, False), serve(18443, True)
    c = http.client.HTTPConnection('127.0.0.1', 18080)
    c.request('GET', '/origin/39D8E03B/0/H.Cache.bin!E_---------------------w', headers={'Host': 'origin.soulframe.com'})
    r = c.getresponse()
    assert (r.status, r.read()) == (200, MANIFEST.read_bytes())
    creds = b'{"email": "me@example.com", "password": "pw"}'
    c.putrequest('POST', '/api/login.php?ct=STM')
    c.putheader('Transfer-Encoding', 'chunked'); c.endheaders()
    c.send(b'%x\r\n%s\r\n0\r\n\r\n' % (len(creds), creds))
    r = c.getresponse()
    me = json.loads(r.read())
    assert (r.status, me['ClientType'], me['NRS'], me['id']) == (200, 'STM', ['127.0.0.1'], admin.accounts()['me@example.com']['id'])
    auth = f'accountId={me["id"]}&nonce={me["Nonce"]}'
    c.request('POST', f'/api/purchase.php?{auth}', body=ezip_encode(b'{"x":1}'), headers={'Content-Encoding': 'ezip'})
    r = c.getresponse(); r.read()
    c.request('GET', '/api/nope.php')
    r = c.getresponse(); r.read()
    assert r.status == 404
    c.request('GET', f'/api/credits.php?{auth}')  # the top-bar wallet follows the saved inventory, not the fixture
    r = c.getresponse()
    assert json.loads(r.read())['PremiumCredits'] == admin.load(admin.inventory_path(me))['PremiumCredits']
    c.request('GET', f'/api/inventory.php?accountId={me["id"]}&nonce=1')  # someone else's accountId: refused
    r = c.getresponse(); r.read()
    assert r.status == 403
    c.request('POST', '/api/login.php', body=b'{"email": "me@example.com", "password": "nope"}')
    r = c.getresponse(); r.read()
    assert r.status == 403
    c.request('GET', f'/api/hub?{auth}&level=CHAMPIONHUB_EU_EN_WIN_0')
    r = c.getresponse()
    assert json.loads(r.read()) == f'hub 127.0.0.1:{HUB_PORT}'
    # What a curious player on the LAN might try (code review): none of it may reach data/ or other files.
    for probe in ('/api/accounts.php', '/api/seed.php', '/api/..\\data\\accounts.php', '/api/C:\\Windows\\win.php',
                  f'/api/accounts\\{me["id"]}\\inventory.php'):
        c.request('GET', probe)
        r = c.getresponse()
        assert (r.status, r.read()) == (404, b''), probe
    c.request('POST', '/api/purchase.php', body=b'{}')  # no session at all, once accounts exist
    r = c.getresponse(); r.read()
    assert r.status == 403
    assert b'"pw"' not in (OUT / '00002_request.bin').read_bytes() and b'<not kept>' in (OUT / '00002_request.bin').read_bytes()
    ctx = ssl.create_default_context(cafile=CA)  # verifies chain *and* hostname, as curl/Schannel do
    with ctx.wrap_socket(socket.create_connection(('127.0.0.1', 18443)), server_hostname='api.soulframe.com') as s:
        s.sendall(b'POST /api/login.php HTTP/1.1\r\nHost: api.soulframe.com\r\nContent-Length: %d\r\n\r\n%s' % (len(creds), creds))
        assert s.recv(100).startswith(b'HTTP/1.1 200')
    rows = [r for l in open(OUT / 'requests.jsonl') if 'n' in (r := json.loads(l))]  # skip the reset from our early close
    assert [r['body_bytes'] for r in rows] == [0, 45, 7, 0, 0, 0, 47, 0, 0, 0, 0, 0, 0, 2, 45] and rows[14]['sni'] == 'api.soulframe.com', rows
    assert (OUT / rows[2]['body_file']).read_bytes() == b'{"x":1}'
    udp = serve_udp(18952)
    socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'tr\x00', ('127.0.0.1', 18952))
    for _ in range(50):
        if any(json.loads(l).get('hex') == '747200' for l in open(OUT / 'requests.jsonl')):
            break
        threading.Event().wait(0.05)
    else:
        raise AssertionError('udp packet not logged')
    udp.close()
    print('selftest ok')


if __name__ == '__main__':
    make_certs()
    if '--selftest' in sys.argv:
        OUT = OUT.with_name(OUT.name + '-selftest')
        selftest()
    else:
        if sys.platform == 'win32':
            # A click in the console starts a QuickEdit selection, which freezes print() and with it every
            # response until a key is pressed (the client then retries every ~30 s). Turn QuickEdit off.
            import ctypes
            k32, mode = ctypes.windll.kernel32, ctypes.c_uint32()
            stdin = k32.GetStdHandle(-10)
            if k32.GetConsoleMode(stdin, ctypes.byref(mode)):
                k32.SetConsoleMode(stdin, (mode.value & ~0x40) | 0x80)  # -ENABLE_QUICK_EDIT_MODE, +EXTENDED_FLAGS
        if '--host' in sys.argv:
            BIND = '0.0.0.0'
        serve(80, False), serve(443, True), serve_udp(NRS_PORT)
        if '--hub' in sys.argv or '--mirror' in sys.argv:  # unfinished, see the top of this file
            hub_relay.serve(BIND, HUB_PORT, mirror='--mirror' in sys.argv,
                            out=lambda line: (print('      ' + line, flush=True), log(event='hub', line=line)))
        else:
            serve_udp(HUB_PORT)
        if sys.platform != 'win32' and os.geteuid() == 0 and 'SUDO_UID' in os.environ:
            # Root was only for ports 80/443 (play.sh): back to the user who ran sudo, so data/, captures/ and
            # certs/ in their clone stay theirs.
            uid, gid = int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
            for p in (CERT.parent, CERT, KEY, CA):
                os.chown(p, uid, gid)
            os.setgroups([]), os.setgid(gid), os.setuid(uid)
        print(f'listening on {BIND}:80, :443 (TCP) and :{NRS_PORT}, :{HUB_PORT} (UDP), logging to {OUT}', flush=True)
        if BIND != '127.0.0.1':
            addrs = sorted({a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)})
            print(f'players join with one of: {", ".join(addrs)}  (Tailscale/ZeroTier: its 100.x / 10.x address)', flush=True)
        try:
            while True:  # an untimed wait() never sees Ctrl+C on Windows; a short timeout does
                threading.Event().wait(0.5)
        except KeyboardInterrupt:
            print('stopped', flush=True)  # handler threads are daemons and die with us
