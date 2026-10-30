"""Turn a live `soulkit api capture` into Phase 3 replay fixtures for tools/dummy_server.py.

For every endpoint in the capture, writes the last response to fixtures/<name>/response.raw (the decoded
body bytes, JSON or not). Your real accountId, nonce, token and display name are replaced with the fake
ones from fixtures/login/response.json. Existing fixtures are never overwritten (login is hand-made).

Usage:  python tools/fixtures_from_capture.py ../soulframe-rust-workspace/output/api-capture/<capture>
"""
import gzip, json, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = ROOT / 'fixtures'


def split_responses(stream: bytes) -> list[bytes]:
    """Decoded bodies of the HTTP/1.1 responses in one received TLS stream, in order."""
    bodies, at = [], 0
    while (start := stream.find(b'HTTP/1.1 ', at)) >= 0:
        head_end = stream.find(b'\r\n\r\n', start)
        if head_end < 0:
            break
        head = stream[start:head_end].decode('latin-1').lower()
        at = head_end + 4
        if 'transfer-encoding: chunked' in head:
            body = b''
            while True:
                line_end = stream.find(b'\r\n', at)
                size = int(stream[at:line_end].split(b';')[0], 16)
                at = line_end + 2 + size + 2
                if not size:
                    break
                body += stream[line_end + 2:line_end + 2 + size]
        else:
            m = re.search(r'content-length: (\d+)', head)
            size = int(m.group(1)) if m else 0
            body, at = stream[at:at + size], at + size
        if 'content-encoding: gzip' in head and body:
            body = gzip.decompress(body)
        bodies.append(body)
    return bodies


def main(capture: pathlib.Path) -> None:
    fake = json.loads((FIXTURES / 'login/response.json').read_text(encoding='utf-8'))
    transactions = json.loads((capture / 'http_transactions.json').read_text(encoding='utf-8'))
    by_stream: dict[int, list[dict]] = {}
    for t in transactions:
        by_stream.setdefault(t['tls_stream_id'], []).append(t)

    latest: dict[str, bytes] = {}
    real: dict[str, str] = {}
    for stream_id, ts in sorted(by_stream.items()):
        bodies = split_responses((capture / f'streams/{stream_id:06d}_received.bin').read_bytes())
        if len(bodies) != len(ts):
            print(f'  stream {stream_id}: {len(ts)} transactions but {len(bodies)} responses, skipped')
            continue
        for t, body in zip(ts, bodies):
            name = t['url'].split('?')[0].rsplit('/', 1)[-1].removesuffix('.php')
            latest[name] = body
            if name == 'login':
                doc = json.loads(body)
                real = {str(doc[k]): str(fake[k]) for k in ('id', 'Nonce', 'Token', 'DisplayName')}

    for name, body in sorted(latest.items()):
        out = FIXTURES / name
        if out.exists():
            print(f'  {name}: exists, kept')
            continue
        for old, new in real.items():
            body = body.replace(old.encode(), new.encode())
        out.mkdir()
        (out / 'response.raw').write_bytes(body)
        print(f'  {name}: {len(body)} B')


if __name__ == '__main__':
    main(pathlib.Path(sys.argv[1]))
