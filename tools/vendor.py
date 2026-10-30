"""Phase 5: getVendorInfo.php built from the vendor's manifest instead of the one captured answer.

The manifest (/SF/Types/Game/AvakotVendorManifest in Packages.bin) is a dynamic vendor: AlwaysOffered items,
RotatedWeekly items, and NumItemsAvailable slots of random items, each picked by AppearanceFrequency and
offered for DurationAvailable hours at a price in RegularPrice/PremiumPrice (findings/0022). The live answer
(fixtures/getVendorInfo) has exactly that shape: 4 always + 13 weekly items with a 2035 expiry, 5 random ones
expiring on the hour, and a top-level Expiry equal to the earliest of those.

ponytail: DE's scheduler and RNG are server-side and unknown, so this is our own deterministic schedule (same
answer for the same hour, every request); weekly items reroll price and Id every Monday 00:00 UTC.

Usage:  python tools/vendor.py [--selftest]      prints the current Avakot stock
"""
import datetime, functools, hashlib, json, pathlib, random, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGES = ROOT.parent / 'soulframe-pipeline/formatted_packages.json'  # ponytail: Oct 2 export, not re-extracted for P16H6
FIXTURE = ROOT / 'fixtures/getVendorInfo/response.raw'
ANCHOR = 1767225600  # 2026-01-01T00:00Z: the schedule is simulated hourly from here, so it never jumps
FAR = 2051240400000  # 2035-01-01T05:00Z (ms), the live answer's expiry for always-offered and weekly items
HOUR, WEEK = 3600, 7 * 86400
MONDAY = 345600  # 1970-01-05 was a Monday
KNOWN = {'/SF/Types/Game/AvakotVendorManifest'}  # ponytail: the one dynamic vendor seen in captures; others replay


@functools.lru_cache(maxsize=None)
def packages():
    """All package data ({path: {attributes, parent}}); loaded once (83 MB, a few seconds)."""
    return json.loads(PACKAGES.read_text(encoding='utf-8'))


@functools.lru_cache(maxsize=None)
def manifest(type_name):
    a = packages()[type_name]['attributes']
    return a['ItemManifest'], a.get('NumItemsAvailable', [0, 0])[0]


def oid(start, *key):
    """A stable 24-hex ObjectId: 4 bytes of start time, 8 bytes of hash, so a rotation gives a new Id."""
    return {'$oid': f'{start:08x}' + hashlib.sha1(repr(key).encode()).hexdigest()[:16]}


def offer(item, start, expiry_ms, rng):
    out = {'StoreItem': item['StoreItem']}
    for key, step in (('RegularPrice', item.get('RegularPriceStep') or 1), ('PremiumPrice', 1)):
        lo, hi = item.get(key, [0, 0])
        if hi:
            p = rng.randrange(lo, hi + 1, step) if hi > lo else lo
            out[key] = [p, p]
    out |= {'Bin': item['Bin'], 'QuantityMultiplier': item['QuantityMultiplier'], 'Expiry': {'$date': {'$numberLong': str(expiry_ms)}}}
    if item.get('PurchaseQuantityLimit'):
        out['PurchaseQuantityLimit'] = item['PurchaseQuantityLimit']
    if item.get('RotatedWeekly'):
        out['RotatedWeekly'] = True
    if item.get('AllowMultipurchase'):
        out['AllowMultipurchase'] = True
    out['Id'] = oid(start, item['StoreItem'], start)
    return out


@functools.lru_cache(maxsize=4)
def schedule(type_name, hour):
    """The random slots at this hour: [(item, start, end)], simulated hour by hour from ANCHOR."""
    items, n = manifest(type_name)
    pool = [i for i in items if not i['AlwaysOffered'] and not i['RotatedWeekly']]
    slots = []
    for h in range(ANCHOR, hour + 1, HOUR):
        slots = [s for s in slots if s[2] > h]
        while len(slots) < n:
            active = {s[0]['StoreItem'] for s in slots}
            cands = [i for i in pool if i['StoreItem'] not in active]
            rng = random.Random(f'{type_name}:{h}:{len(slots)}')
            item = rng.choices(cands, [i['AppearanceFrequency'] for i in cands])[0]
            lo, hi = item['DurationAvailable']
            slots.append((item, h, h + rng.randint(lo, hi) * HOUR))
    return slots


def vendor_info(type_name='/SF/Types/Game/AvakotVendorManifest', now=None):
    now = int(time.time() if now is None else now)
    items, _ = manifest(type_name)
    week = now - (now - MONDAY) % WEEK
    out = []
    for i in items:
        if i['AlwaysOffered']:
            out.append(offer(i, ANCHOR, FAR, random.Random(i['StoreItem'])))
        elif i['RotatedWeekly']:
            out.append(offer(i, week, FAR, random.Random(f'{i["StoreItem"]}:{week}')))
    slots = schedule(type_name, now - now % HOUR)
    for item, start, end in slots:
        out.append(offer(item, start, end * 1000, random.Random(f'{item["StoreItem"]}:{start}')))
    expiry = min((end for _, _, end in slots), default=now + HOUR)
    captured = json.loads(FIXTURE.read_text(encoding='utf-8'))['VendorInfo']
    return {'VendorInfo': {'_id': captured['_id'], 'TypeName': type_name, 'ItemManifest': out,
                           'Expiry': {'$date': {'$numberLong': str(expiry * 1000)}}}}


def selftest():
    live = json.loads(FIXTURE.read_text(encoding='utf-8'))['VendorInfo']
    t = 1793215405  # the live capture's worldState Time
    v = vendor_info(now=t)['VendorInfo']
    ms = v['ItemManifest']
    far = [o for o in ms if o['Expiry']['$date']['$numberLong'] == str(FAR)]
    rand = [o for o in ms if o not in far]
    # Same shape as the live answer: same always + weekly items, 5 random ones, Expiry = earliest random expiry.
    assert sorted(o['StoreItem'] for o in far) == sorted(o['StoreItem'] for o in live['ItemManifest']
                                                         if o['Expiry']['$date']['$numberLong'] == str(FAR))
    assert len(rand) == 5 and len({o['StoreItem'] for o in rand}) == 5
    ends = [int(o['Expiry']['$date']['$numberLong']) for o in rand]
    assert all(e > t * 1000 and e % (HOUR * 1000) == 0 for e in ends)
    assert v['Expiry']['$date']['$numberLong'] == str(min(ends))
    assert set(live['ItemManifest'][0]) == set(ms[0])  # HealingPotion: same fields as live
    items = {i['StoreItem']: i for i in manifest(v['TypeName'])[0]}
    for o in ms:
        i, (key, (p, _)) = items[o['StoreItem']], next((k, o[k]) for k in ('RegularPrice', 'PremiumPrice') if k in o)
        assert i[key][0] <= p <= i[key][1], o
    assert vendor_info(now=t + 60) == vendor_info(now=t)  # stable within the hour
    nxt = vendor_info(now=min(ends) // 1000)['VendorInfo']['ItemManifest']
    assert {o['Id']['$oid'] for o in nxt} != {o['Id']['$oid'] for o in ms}  # the expired slot was refilled
    assert vendor_info(now=t + WEEK)['VendorInfo']['ItemManifest'][4]['Id'] != ms[4]['Id']  # weekly Ids roll
    print('selftest ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        selftest()
    else:
        for o in vendor_info()['VendorInfo']['ItemManifest']:
            exp = int(o['Expiry']['$date']['$numberLong']) // 1000
            print(f"{o['StoreItem'].rsplit('/', 1)[-1]:32} {o.get('RegularPrice') or o.get('PremiumPrice')}  "
                  f"until {datetime.datetime.fromtimestamp(exp, datetime.timezone.utc):%Y-%m-%d %H:%M}Z")
