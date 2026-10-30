"""Merge soulkit api-capture runs into endpoints.json (PLAN Phase 1, step 2).

Usage: python tools/catalog.py <capture_dir> [<capture_dir> ...]
Writes endpoints.json in the repo root. Only shapes are recorded (query keys, sizes,
content types), never values, so the output is safe to keep in the repo.
"""
import json
import re
import sys
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "endpoints.json"


def norm_path(host: str, path: str) -> str:
    # Asset URLs carry a per-file hash; collapse them to one entry.
    if host == "content.soulframe.com":
        return "/0/<asset path>!<hash>"
    if host == "origin.soulframe.com":
        return re.sub(r"/origin/[0-9A-F]{8}/", "/origin/<hex32>/", path)
    return path


def records(cap: Path) -> Iterator[tuple]:
    """Yield (method, host, path, query_keys, req_ctype, req_bytes, status, resp_bytes, layer)."""
    reqs = {r["id"]: r for r in json.loads((cap / "http_requests.json").read_text("utf8"))}
    for t in json.loads((cap / "http_transactions.json").read_text("utf8")):
        rq = reqs.get(t["request_id"], {})
        host = rq.get("host") or re.match(r"https?://([^/:]+)", t["url"]).group(1)
        path, _, query = t["url"].split(host, 1)[1].lstrip(":0123456789").partition("?")
        keys = sorted(k for k in (p.split("=")[0] for p in query.split("&")) if k)
        yield (t["method"], host, norm_path(host, path), keys,
               rq.get("headers", {}).get("content-type"), rq.get("body_bytes", 0),
               t["status_code"], t["response_body_bytes"], "libcurl/tls")
    # WinHTTP traffic (content manifest + assets) only lives in events.jsonl.
    for line in (cap / "events.jsonl").read_text("utf8").splitlines():
        e = json.loads(line)
        r = e.get("request")
        if e["event"] != "request_closed" or not r or r["host"] == "<unknown>":
            continue
        path = re.sub(r"^https?://[^/]+", "", r["url"]).split("?")[0]
        yield (r["method"], r["host"], norm_path(r["host"], path), [], None,
               r["request_bytes"], r["status_code"], r["response_bytes"], "winhttp")


def main(caps: list[str]) -> None:
    old = json.loads(OUT.read_text("utf8")) if OUT.exists() else {"endpoints": [], "captures": []}
    eps = {(e["method"], e["host"], e["path"]): e for e in old["endpoints"]}
    merged = old.get("captures", [])
    for cap in map(Path, caps):
        if cap.name in merged:
            print(f"skip {cap.name} (already merged)")
            continue
        merged.append(cap.name)
        for m, host, path, keys, ctype, qb, status, rb, layer in records(cap):
            e = eps.setdefault((m, host, path), {
                "method": m, "host": host, "path": path, "layer": layer, "query_keys": [],
                "request_content_types": [], "statuses": [], "calls": 0,
                "max_request_bytes": 0, "max_response_bytes": 0, "captures": [],
                "fixture": None,
            })
            e["query_keys"] = sorted(set(e["query_keys"]) | set(keys))
            if ctype and ctype not in e["request_content_types"]:
                e["request_content_types"].append(ctype)
            if status not in e["statuses"]:
                e["statuses"].append(status)
            e["calls"] += 1
            e["max_request_bytes"] = max(e["max_request_bytes"], qb or 0)
            e["max_response_bytes"] = max(e["max_response_bytes"], rb or 0)
            if cap.name not in e["captures"]:
                e["captures"].append(cap.name)
    out = sorted(eps.values(), key=lambda e: (e["host"], e["path"], e["method"]))
    OUT.write_text(json.dumps({"build": "P16H6", "captures": merged, "endpoints": out}, indent=2) + "\n", "utf8")
    print(f"{len(out)} endpoints -> {OUT}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
