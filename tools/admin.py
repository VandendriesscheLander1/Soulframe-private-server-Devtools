"""Phase 4 state: the saved inventory that tools/dummy_server.py serves as inventory.php, the handlers that
change it from client requests (HANDLERS: purchase, missionInventoryUpdate, ...), and an admin CLI.

Accounts (Phase 6): data/accounts.json, one per login email. The first login creates the account and sets its
password; each gets data/accounts/<id>/inventory.json: a fresh account (tutorial first, see fresh()), or a copy of
data/seed.json if you put an inventory there. The first account takes over an existing data/inventory.json.
The client reads the inventory at login, so restart the game to see a change.

Usage:  python tools/admin.py [--as <email>] give <List> <ItemType> [count]   e.g. give MiscItems /SF/Types/PickUps/Resources/Iron 50
        python tools/admin.py [--as <email>] set <Key> <json>                   e.g. set RegularCredits 99999
        python tools/admin.py [--as <email>] show [Key]
        python tools/admin.py [--as <email>] load <inventory.json>              replace the inventory with that file
        python tools/admin.py [--as <email>] reset                              back to the starting inventory
        python tools/admin.py accounts                                          list them
        python tools/admin.py --selftest
Without --as: the only account, or data/inventory.json while there are none.
"""
import hashlib, hmac, json, math, os, secrets, pathlib, random, sys, tempfile, time, zlib
import vendor as vendor_rules  # tools/vendor.py: the current vendor stock + package data

import shop_rolls  # tools/shop_rolls.py: roll_tempers, the native weapon temper roll (ShopsDecode.md)

ROOT = pathlib.Path(__file__).resolve().parent.parent

SEED = ROOT / 'data/seed.json'  # an inventory new accounts start from instead of a fresh one, if you put one there
FIXTURE = ROOT / 'fixtures/inventory/response.json'  # the live alt's, just past the tutorial
INV = ROOT / 'data/inventory.json'  # before any account exists; the first account takes it over
ACCOUNTS = ROOT / 'data/accounts.json'
QUALITIES = ('IQ_WORN', 'IQ_MILITARY', 'IQ_OFFICER', 'IQ_NOBLE', 'IQ_MASTERWORK', 'IQ_LEGENDARY')  # mQuality 1..6
GEAR = {'Suits', 'Melee', 'LongGuns', 'WeaponSkins', 'Upgrades', 'KubrowPets'}  # entries with an ItemId, not stacks


def attr(path, key):
    """A package attribute, inherited through the parent chain (shop_rolls.attr)."""
    shop_rolls.P = shop_rolls.P or vendor_rules.packages()
    return shop_rolls.attr(path, key)


def fresh(inv):
    """A brand-new account, from the alt's inventory (FIXTURE) minus its progress: FirstLoginUtils.IsNewPlayer is
    Q1WakeUp neither active nor done, which starts the tutorial; its faction choice asks for the starting gear.
    ponytail: no capture of a new account exists; this is the alt with its progress cleared. If the tutorial trips
    over a key, compare with a real new account's inventory.php."""
    inv = {k: v for k, v in inv.items() if k not in ('SupportedSyndicate', 'WorldSpawnPosition', 'MotherCustomization')}
    for key, value in inv.items():
        if isinstance(value, list) and key != 'CurrentLoadOutIds':  # Quests, Suits, Melee, MiscItems, XPInfo, ...
            inv[key] = []
    inv |= {'RegularCredits': 0, 'ReceivedStartingGear': False, 'Created': {'$date': {'$numberLong': str(int(time.time() * 1000))}}}
    # The presets stay (FactionChoice fills preset 0 with the new suit), without the alt's suit and weapon in them.
    inv['LoadOutPresets'] = {k: [{f: v for f, v in p.items() if f not in ('m', 's')} for p in presets]
                             for k, presets in inv['LoadOutPresets'].items()}
    return inv


def starting_inventory():
    if SEED.exists():
        inv = json.loads(SEED.read_text(encoding='utf-8'))
        if not isinstance(inv, dict):
            raise ValueError(f'{SEED} is not an inventory (a JSON object)')
        return inv
    return fresh(json.loads(FIXTURE.read_text(encoding='utf-8')))


def load(path=None):
    path = path or INV
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        write_json(path, starting_inventory())
    return json.loads(path.read_text(encoding='utf-8'))


def save(inv, path=None):
    write_json(path or INV, inv)


def write_json(path, doc):
    tmp = path.with_suffix('.tmp')  # the server may read it at any moment: never serve half a file
    tmp.write_text(json.dumps(doc, ensure_ascii=False), encoding='utf-8')
    tmp.replace(path)


def accounts():
    return json.loads(ACCOUNTS.read_text(encoding='utf-8')) if ACCOUNTS.exists() else {}


def inventory_path(account):
    return ACCOUNTS.parent / 'accounts' / account['id'] / 'inventory.json'


def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200_000).hex()


def login(email, password):
    """login.php body {email, password, ...}: the account for this email with a fresh Nonce, created on first login
    (the password then becomes its password). None if the password is wrong. Callers hold the server's state lock.
    The client already hashes the password; it's salted and hashed again so data/accounts.json holds nothing reusable."""
    accts, key = accounts(), email.strip().lower()
    if not key:
        return None
    acct = accts.get(key)
    if acct is None:
        salt = secrets.token_hex(16)
        acct = {'id': new_oid(), 'email': key, 'DisplayName': key.split('@')[0][:24] or 'Player',
                'salt': salt, 'pw': pw_hash(password, salt)}
        if not accts and INV.exists():  # the single-account inventory from before accounts existed
            inventory_path(acct).parent.mkdir(parents=True, exist_ok=True)
            INV.replace(inventory_path(acct))
    elif not hmac.compare_digest(acct['pw'], pw_hash(password, acct['salt'])):
        return None
    # Same shapes as DE's login (fixtures/login): a 31-bit Nonce, sent back on every call as &nonce=, and an 80-digit
    # Token. A 51-bit Nonce and a Token with letters crashed the client right after login (assertion at 0x105ec2f).
    acct['Nonce'] = secrets.randbelow(2**31 - 1) + 1
    acct['Token'] = ''.join(secrets.choice('0123456789') for _ in range(80))
    accts[key] = acct
    ACCOUNTS.parent.mkdir(exist_ok=True)
    write_json(ACCOUNTS, accts)
    return acct


def session(account_id, nonce):
    """The account an API call (?accountId=&nonce=) belongs to, or None if the pair doesn't match its latest login."""
    return next((a for a in accounts().values() if a['id'] == account_id and str(a.get('Nonce')) == nonce), None)


def give(inv, list_name, item_type, count=1):
    """Stack items ({ItemType, ItemCount}). Not for gear with an ItemId (Melee, Suits, ...)."""
    items = inv.setdefault(list_name, [])
    for it in items:
        if it.get('ItemType') == item_type:
            if 'ItemCount' not in it:
                raise ValueError(f'{list_name} holds gear with ItemIds, not stacks; give only does stacks')
            it['ItemCount'] += count
            return it
    items.append(it := {'ItemCount': count, 'ItemType': item_type})
    return it


def new_oid():
    """A fresh Mongo-style ObjectId: 4 bytes of time, 8 random."""
    return f'{int(time.time()):08x}{os.urandom(8).hex()}'


def add_item(inv, list_name, item_type, count=1):
    """Give count of item_type: a stack, or new gear entries ({ItemId, ItemType}) when the list holds gear.
    Returns the entries for an InventoryChanges answer."""
    items = inv.setdefault(list_name, [])
    if list_name in GEAR or any('ItemId' in i for i in items):
        new = [{'ItemId': {'$oid': new_oid()}, 'ItemType': item_type} for _ in range(count)]
        items.extend(new)
        return new
    give(inv, list_name, item_type, count)
    return [{'ItemType': item_type, 'ItemCount': count}]


def upsert(items, key, entry):
    """Replace the entry with the same key (e.g. ItemType, Name), or append it."""
    for i, it in enumerate(items):
        if it.get(key) == entry.get(key):
            items[i] = entry
            return
    items.append(entry)


def stack_list_for(inv, item_type):
    """Which inventory list a stack item lives in: wherever it already is, else a guess from its path."""
    for name, items in inv.items():
        if isinstance(items, list) and any(isinstance(i, dict) and i.get('ItemType') == item_type for i in items):
            return name
    # ponytail: path guess for items the account has never had (an unowned weapon always goes to Melee, though
    # some live in LongGuns); fix from a capture when one lands wrong
    for part, name in (('/Consumables/', 'Consumables'), ('/Recipes/', 'Recipes'), ('/Weapons/', 'Melee'),
                       ('/Upgrades/Skins/', 'WeaponSkins'), ('/Upgrades/', 'RawUpgrades')):
        if part in item_type:
            return name
    return 'MiscItems'


def mission_inventory_update(inv, body):
    """missionInventoryUpdate.php: the client reports what changed, as Warframe's does. Stacks
    ({ItemType, ItemCount}) and RegularCredits are deltas; gear ({ItemId, XP}) gains XP (box run
    20261029T173930: the suit reported XP 4000 against 21498 owned). Each update reports only what's new since
    the last one (box run 20261029T175412: a pickup of 5 QuenchingAcid, suit XP 2255 then 2000). The real
    answer is an empty body. CurrentLoadOutIds is ignored on purpose: it drops the sleeve and holster after
    the first update of every session (same run), so saving it would wipe them (findings/0019).
    ponytail: trusts the client (Phase 5 checks rewards)."""
    for key, value in body.items():
        if key == 'RegularCredits' and isinstance(value, int):
            inv['RegularCredits'] = inv.get('RegularCredits', 0) + value
        elif key == 'WorldSpawnPosition':
            inv[key] = value
        elif key == 'LoreFragmentScans':
            lore_fragments(inv, body)
        elif key == 'ChallengeProgress':
            challenge_progress(inv, body)
        elif key == 'Affiliations' and isinstance(value, dict):
            affiliations(inv, value)
        elif isinstance(value, list) and all(isinstance(i, dict) for i in value):
            owned = {g['ItemId']['$oid']: g for g in inv.get(key, []) if isinstance(g, dict) and 'ItemId' in g}
            for i in value:
                oid = i.get('ItemId', {}).get('$oid')
                if oid == '0' * 24:  # a new item, e.g. a picked-up rune (box run 20261029T181616, request 349)
                    for _ in range(i.get('ItemCount', 1)):
                        inv.setdefault(key, []).append({'ItemId': {'$oid': new_oid()}, 'ItemType': i['ItemType'],
                                                        **({'UpgradeFingerprint': i['UpgradeFingerprint']}
                                                           if i.get('UpgradeFingerprint') else {})})
                elif oid:
                    if (g := owned.get(oid)) and i.get('XP'):
                        g['XP'] = g.get('XP', 0) + i['XP']
                elif 'ItemType' in i and 'ItemCount' in i:
                    give(inv, key, i['ItemType'], i['ItemCount'])


def affiliations(inv, value):
    """Faction tale progress: {Tag: {EncounterPaths: {"0": path, ...}}} (box run 20261029T181616).
    ponytail: stored as a list in index order, the inventory's own shape for it ([] so far) is unconfirmed;
    other fields (Standing, ...) not seen yet, so not applied."""
    for tag, aff in value.items():
        entry = next((a for a in inv.setdefault('Affiliations', []) if a.get('Tag') == tag), None)
        if entry is None:
            inv['Affiliations'].append(entry := {'Tag': tag})
        if isinstance(paths := aff.get('EncounterPaths'), dict):
            entry['EncounterPaths'] = [paths[k] for k in sorted(paths, key=int)]


def recipe(name):
    """A blueprint's crafting fields from package data, parents resolved, by the path the client sends (RecipeName).
    ponytail: package data is the Oct 2 export, not re-extracted for P16H6."""
    if attr(name, 'ResultItem') is None:
        raise ValueError(f'unknown recipe {name}')
    return {k: attr(name, k) for k in ('Ingredients', 'BuildPrice', 'BuildTime', 'ConsumeOnUse', 'ResultItem',
                                       'Quality', 'SkipBuildTimePrice')}


def start_recipe(inv, body):
    """startRecipe.php: take the ingredients, credits and (unless ConsumeOnUse is 0) the blueprint, and
    queue it in PendingRecipes. Answer {RecipeId, CompletionDate} (live capture 20261029T160518709Z).
    ponytail: ignores the optional-ingredient choice (Ids/Types/Category, BonusTier) and trusts the client that
    you have the ingredients."""
    r = recipe(body['RecipeName'])
    for ing in r['Ingredients'] or []:
        give(inv, stack_list_for(inv, ing['ItemType']), ing['ItemType'], -ing['ItemCount'])
    inv['RegularCredits'] = inv.get('RegularCredits', 0) - (r['BuildPrice'] or 0)
    if r['ConsumeOnUse'] != 0:
        give(inv, 'Recipes', body['RecipeName'], -1)
    done = {'$date': {'$numberLong': str(int((time.time() + (r['BuildTime'] or 0)) * 1000))}}
    pending = {'CompletionDate': done, 'ItemId': {'$oid': new_oid()}, 'ItemType': body['RecipeName']}
    inv.setdefault('PendingRecipes', []).append(pending)
    return {'RecipeId': pending['ItemId'], 'CompletionDate': done}


def rush_cost(price, build_time, left):
    """SFUtilities.CalculateRushCost: half the SkipBuildTimePrice plus the share of the build time still left."""
    return math.ceil(min(price, price * 0.5 + price * (left / build_time)))


def new_weapon(store_item, quality):
    """A crafted weapon as the inventory holds one: Quality, AspectType (the store item's DefaultUpgrades aspect
    manifest) and AspectFingerprint {buffs: [{Tag, Value}], curses: []} rolled by the native temper roll.
    ponytail: DE's craft seed is unknown, so the roll is seeded randomly; never any curses."""
    item_type = attr(store_item, 'TypeName')
    aspect = next((d['ItemType'] for d in attr(store_item, 'DefaultUpgrades') or [] if d.get('Slot', 0) < 0), None)
    state = ((zlib.crc32(item_type.encode()) or 1) << 32) | int.from_bytes(os.urandom(4), 'little')
    tempers = shop_rolls.roll_tempers(aspect, QUALITIES.index(quality) + 1, state) if aspect else []
    weapon = {'AspectFingerprint': {'buffs': [{'Tag': e['Tag'], 'Value': v} for e, v in tempers], 'curses': []},
              'AspectType': aspect, 'ItemId': {'$oid': new_oid()}, 'ItemType': item_type, 'Quality': quality, 'XP': 0}
    return weapon if aspect else {k: v for k, v in weapon.items() if k not in ('AspectFingerprint', 'AspectType')}


def store_item_for(path):
    """The store item of an item type (/SF/Weapons/X -> /SF/StoreItems/Weapons/X), or the path if it already is one."""
    store = path.replace('/SF/', '/SF/StoreItems/', 1)
    return store if '/StoreItems/' not in path and attr(store, 'TypeName') else path


def grant(inv, store_item, changes, quality=None, count=1):
    """Give count of a store item where its ProductCategory says, into changes (an InventoryChanges): a weapon with
    tempers when a quality is given, other gear as new entries, the rest as a stack."""
    item_type = attr(store_item, 'TypeName') or store_item.replace('/StoreItems', '', 1)
    list_name = attr(store_item, 'ProductCategory') or stack_list_for(inv, item_type)
    if attr(store_item, 'DefaultUpgrades') and quality:
        for _ in range(count):
            inv.setdefault(list_name, []).append(new := new_weapon(store_item, quality))
            changes.setdefault(list_name, []).append(new)
    else:
        changes.setdefault(list_name, []).extend(add_item(inv, list_name, item_type, count))


def claim_completed_recipe(inv, body):
    """claimCompletedRecipe.php {RecipeIds, Ancestor}: give each finished pending recipe's result. With ?rush=1
    (box run 20261029T190809, request 470; Foundry.lua ClaimOrRush) an unfinished one is finished for its rush
    cost in PremiumCredits. Foundry.lua reads InventoryChanges.Melee[1].Quality from the answer.
    ponytail: Ancestor isn't checked; one result per craft; a crafted weapon gets the blueprint's Quality
    (TierC weapon blueprints: IQ_OFFICER), though owned crafts of one blueprint vary (WORN..MASTERWORK)."""
    ids = {i['$oid'] for i in body['RecipeIds']}
    rush = body.get('_query', {}).get('rush') == '1'
    changes = {}
    for p in [p for p in inv.get('PendingRecipes', []) if p['ItemId']['$oid'] in ids]:
        r = recipe(p['ItemType'])
        left = int(p['CompletionDate']['$date']['$numberLong']) / 1000 - time.time()
        if left > 0:
            if not rush:
                continue
            cost = rush_cost(r['SkipBuildTimePrice'] or 0, r['BuildTime'], left)
            inv['PremiumCredits'] = inv.get('PremiumCredits', 0) - cost
            changes['PremiumCredits'] = changes.get('PremiumCredits', 0) - cost
        inv['PendingRecipes'].remove(p)
        grant(inv, r['ResultItem'], changes, r['Quality'])
    return {'InventoryChanges': changes}


def strings(doc):
    """Every string in a JSON document, depth first."""
    if isinstance(doc, str):
        yield doc
    elif isinstance(doc, dict | list):
        for v in doc.values() if isinstance(doc, dict) else doc:
            yield from strings(v)


def quest_control(inv, body):
    """questControl.php?action=completeTask (live capture 20261028T182107549Z; the exe also has startWithoutPrereqs):
    walk the quest's graph from package data (Nodes, Links). A task's OnCompleted fires its links (Activate /
    Deactivate other nodes); reaching the EndQuestNode completes the quest ({Completed: <end node>, CompletionDate},
    as in the alt's inventory). Answer {InventoryChanges: {Quests: [entry], ...node rewards}}, as live.
    The body was never decoded (live EZIP has a real RSA key), so it's read by value: the quest is the
    /SF/Types/Quests/ path in it, the task any string that is one of its NodeIds or Tags (QuestLib completes by either).
    ponytail: OnPass links, counter nodes, XpReward, Lore and syndicate standing are not applied."""
    action = body.get('_query', {}).get('action', '')
    found = list(strings({k: v for k, v in body.items() if k != '_query'}))
    quest = next((attr(s, 'TypeName') or s for s in found if '/Types/Quests/' in s), None)
    nodes = {n['NodeId']: n for n in attr(quest, 'Nodes') or [] if isinstance(n, dict) and 'NodeId' in n}
    if not nodes:
        raise ValueError(f'questControl {action}: no quest I know in {found}')
    quests = inv.setdefault('Quests', [])
    entry = next((q for q in quests if q.get('ItemType') == quest), None)
    if entry is None:
        quests.append(entry := {'ItemType': quest, 'Progress': {'Current': []}})
    if 'Completed' in entry:
        return {'InventoryChanges': {'Quests': [entry]}}
    current, changes = entry.setdefault('Progress', {}).setdefault('Current', []), {}

    def fire(node_id, port):
        for link in attr(quest, 'Links') or []:
            if link['FromNode'] != node_id or link['FromPort'] != port:
                continue
            to = link['ToNode']
            if link['ToPort'] == 'Deactivate' and to in current:
                current.remove(to)
            elif link['ToPort'] == 'Activate' and nodes.get(to, {}).get('Type', '').endswith('/EndQuestNode'):
                entry.clear()
                entry.update({'Completed': to, 'CompletionDate': {'$date': {'$numberLong': str(int(time.time() * 1000))}},
                              'ItemType': quest})
                return
            elif link['ToPort'] == 'Activate' and to not in current:
                current.append(to)

    if action.startswith('start'):
        fire('START', 'OnStarted')
    elif action == 'completeTask':
        tags = {n.get('Tag'): i for i, n in nodes.items() if n.get('Tag')}
        task = next((s if s in nodes else tags[s] for s in found if s in nodes or s in tags), None)
        if task is None:
            raise ValueError(f'questControl completeTask: no task of {quest} in {found}')
        if task in current:
            current.remove(task)
        for reward in nodes[task].get('Rewards') or []:
            grant(inv, reward, changes)
        fire(task, 'OnCompleted')
    else:
        print(f'  !!  questControl action {action!r} not handled; body {found}', flush=True)
    return {'InventoryChanges': {'Quests': [entry]} | changes}


def give_starting_gear(inv, body):
    """giveStartingGear.php (Warframe's name; not seen in a capture yet): FactionChoice sends the chosen faction's soul,
    weapon and armour skins (FirstLoginUtils.GetInitialFactionLoadouts), then syncs the inventory. Every item path in
    the body is given once. The alt's starter sword was IQ_MILITARY."""
    changes = {}
    for path in set(strings(body)):
        if path.startswith('/SF/') and attr(store := store_item_for(path), 'ProductCategory'):
            grant(inv, store, changes, 'IQ_MILITARY')
    inv['ReceivedStartingGear'] = True
    return {'InventoryChanges': changes}


def dev_cheats(inv, body):
    """devCheats.php: the devs' cheat endpoint (DevImGuiTools posts &RerollAspect= to it, then syncs the inventory).
    Ours, from the F9 panel (dev/dev.lua): &AddItem=<item or store item path>&Count=n[&Quality=IQ_...], &Credits=n.
    dummy_server.py only takes it from this PC."""
    q = body.get('_query', {})
    changes = {}
    if item := q.get('AddItem'):
        store, count = store_item_for(item), max(1, min(int(q.get('Count', 1)), 9999))
        if attr(store, 'ProductCategory'):
            grant(inv, store, changes, q.get('Quality') if q.get('Quality') in QUALITIES else 'IQ_LEGENDARY', count)
        elif item in vendor_rules.packages():  # resources have no store item: a stack of the type itself
            changes.setdefault(name := stack_list_for(inv, item), []).extend(add_item(inv, name, item, count))
        else:
            raise ValueError(f'no item {item}')
    if credits := int(q.get('Credits', 0)):
        inv['RegularCredits'] = inv.get('RegularCredits', 0) + credits
        changes['RegularCredits'] = credits
    return {'InventoryChanges': changes}


def dismantle_loot(item):
    """What dismantling gear gives: SFBaseGameRules.DismantleTables[ItemOrigin][Quality], a drop table.
    ponytail: per pool, min..max_drops weighted picks of quantity min..max; drop_chance and item_count ignored
    (meaning unconfirmed)."""
    tables = attr('/SF/Types/Game/SFBaseGameRules', 'DismantleTables') or {}
    table = tables.get(attr(item['ItemType'], 'ItemOrigin') or 'IO_NONE', {}).get(item.get('Quality') or 'IQ_NONE')
    loot = {}
    for pool in vendor_rules.packages().get(table, {}).get('drop_table', {}).get('pools', []):
        for _ in range(random.randint(pool['min_drops'], pool['max_drops'])):
            i = random.choices(pool['items'], [i['probability'] for i in pool['items']])[0]
            res = i['path'].rsplit('/', 1)[0] + '/' + (i['quantity'].get('pickup_item_type') or i['name'])
            loot[res] = loot.get(res, 0) + random.randint(i['quantity']['min'], i['quantity']['max'])
    return [{'ItemType': t, 'ItemCount': n} for t, n in loot.items()]


def sell(inv, body):
    """sell.php {Items: {List: [{String: ItemId, Count}]}, SellPrice, SellCurrency} (box run 20261029T190809,
    request 424, a dismantle). SC_Dismantle answers {"inventoryChanges": {"MiscItems": [...]}}, lowercase, as
    Character.lua OnItemDismantled reads it; a plain sale adds SellPrice credits and the client ignores the answer.
    ponytail: a stack is assumed to be sent by ItemType in String; SellPrice is taken as the total."""
    loot = []
    for list_name, items in body['Items'].items():
        for it in items:
            g = next((g for g in inv.get(list_name, []) if g.get('ItemId', {}).get('$oid') == it['String']), None)
            if g is None:
                give(inv, list_name, it['String'], -it.get('Count', 1))
                continue
            inv[list_name].remove(g)
            if body.get('SellCurrency') == 'SC_Dismantle':
                loot += dismantle_loot(g)
    if body.get('SellCurrency') != 'SC_Dismantle':
        inv['RegularCredits'] = inv.get('RegularCredits', 0) + (body.get('SellPrice') or 0)
        return None
    for i in loot:
        give(inv, stack_list_for(inv, i['ItemType']), i['ItemType'], i['ItemCount'])
    return {'inventoryChanges': {'MiscItems': loot}}


def save_loadout(inv, body):
    """saveLoadout.php: {List: {ItemId: {config index: config}}}, saved into the item's Configs in the
    inventory's compact form (empty fields dropped). The real answer isn't known; empty for now.
    ponytail: LoadOuts presets and lists the inventory doesn't have (OperatorLoadOuts, ...) are skipped."""
    for list_name, items in body.items():
        owned = {g['ItemId']['$oid']: g for g in inv.get(list_name, []) if isinstance(g, dict) and 'ItemId' in g}
        for oid, configs in (items.items() if isinstance(items, dict) else ()):
            if (g := owned.get(oid)) is None or not isinstance(configs, dict):
                continue
            for idx, cfg in configs.items():
                if not idx.isdigit():
                    continue
                g.setdefault('Configs', [])
                g['Configs'] += [{}] * (int(idx) + 1 - len(g['Configs']))
                g['Configs'][int(idx)] = {k: v for k, v in cfg.items() if v not in ({}, [], '')}


def purchase(inv, body, vendor=None):
    """purchase.php: buy a vendor item. Returns the InventoryChanges answer the client expects."""
    p = body['PurchaseParams']
    vendor = vendor or vendor_rules.vendor_info()['VendorInfo']
    item_id = json.loads(p.get('ExtraPurchaseInfoJson') or '{}').get('ItemId')
    offers = vendor['ItemManifest']
    offer = next((o for o in offers if o['Id']['$oid'] == item_id), None) or \
        next((o for o in offers if o['StoreItem'] == p['StoreItem']), None)
    if offer is None:
        raise ValueError(f'{p["StoreItem"]} not sold by {vendor["TypeName"]}')
    qty = p.get('Quantity', 1)
    # Purchase history, as in a live inventory (capture 20261029T160518709Z): one entry per vendor and offer.
    # Offers rotate (tools/vendor.py), so entries past their Expiry are dropped.
    vendors = inv.setdefault('RecentVendorPurchases', [])
    bought = next((v for v in vendors if v['VendorType'] == vendor['TypeName']), None)
    if bought is None:
        vendors.append(bought := {'PurchaseHistory': [], 'VendorType': vendor['TypeName']})
    now_ms = time.time() * 1000
    bought['PurchaseHistory'] = [h for h in bought['PurchaseHistory'] if int(h['Expiry']['$date']['$numberLong']) > now_ms]
    hist = next((h for h in bought['PurchaseHistory'] if h['ItemId'] == offer['Id']['$oid']), None)
    if hist is None:
        bought['PurchaseHistory'].append(hist := {'Expiry': offer['Expiry'], 'ItemId': offer['Id']['$oid'], 'NumPurchased': 0})
    if hist['NumPurchased'] + qty > offer.get('PurchaseQuantityLimit', float('inf')):
        return {'InventoryChanges': {}}  # ponytail: DE's refusal answer is unknown; "nothing changed" keeps the client in step
    hist['NumPurchased'] += qty
    item_type = p['StoreItem'].replace('/StoreItems', '', 1)
    list_name = stack_list_for(inv, item_type)
    count = qty * offer.get('QuantityMultiplier', 1)
    give(inv, list_name, item_type, count)
    changes = {list_name: [{'ItemType': item_type, 'ItemCount': count}]}
    for price_key, wallet in (('RegularPrice', 'RegularCredits'), ('PremiumPrice', 'PremiumCredits')):
        if price_key in offer:
            cost = offer[price_key][0] * qty
            inv[wallet] = inv.get(wallet, 0) - cost
            changes[wallet] = -cost
    changes['NewVendorPurchase'] = {'VendorType': vendor['TypeName'], 'PurchaseHistory': [hist]}
    return {'InventoryChanges': changes}


def challenge_progress(inv, body):
    """updateChallengeProgress.php: latest progress per challenge name. The real answer is empty."""
    for c in body.get('ChallengeProgress', []):
        upsert(inv.setdefault('ChallengeProgress', []), 'Name', c)


def lore_fragments(inv, body):
    """loreFragments.php: saves scans. {"LoreFragment": ...} is ignored for now (meaning unknown)."""
    for scan in body.get('LoreFragmentScans', []):
        upsert(inv.setdefault('LoreFragmentScans', []), 'ItemType', scan)


# endpoint name -> handler(inv, body). A handler's return value (if any) becomes the JSON response.
HANDLERS = {'missionInventoryUpdate': mission_inventory_update, 'purchase': purchase,
            'updateChallengeProgress': challenge_progress, 'loreFragments': lore_fragments,
            'startRecipe': start_recipe, 'claimCompletedRecipe': claim_completed_recipe, 'saveLoadout': save_loadout,
            'sell': sell, 'questControl': quest_control, 'giveStartingGear': give_starting_gear, 'devCheats': dev_cheats}


def main(args):
    global INV
    match args:
        case ['--as', email, *rest]:
            if (acct := accounts().get(email.strip().lower())) is None:
                raise SystemExit(f'no account {email}; see: python tools/admin.py accounts')
            INV = inventory_path(acct)
            return main(rest)
        case [cmd, *_] if cmd in ('give', 'set', 'show', 'load', 'reset') and len(accts := accounts()) > 1:
            raise SystemExit(f'{len(accts)} accounts: pick one with --as <email>')
        case [cmd, *_] if cmd in ('give', 'set', 'show', 'load', 'reset') and (accts := accounts()):
            INV = inventory_path(next(iter(accts.values())))
    match args:
        case ['give', list_name, item_type, *n]:
            inv = load()
            print(give(inv, list_name, item_type, int(n[0]) if n else 1))
            save(inv)
        case ['set', key, value]:
            inv = load()
            inv[key] = json.loads(value)
            save(inv)
        case ['show', *key]:
            inv = load()
            print(json.dumps(inv[key[0]] if key else sorted(inv), indent=1, ensure_ascii=False))
        case ['load', file]:
            inv = json.loads(pathlib.Path(file).read_text(encoding='utf-8'))
            if not isinstance(inv, dict):
                raise SystemExit(f'{file} is not an inventory (a JSON object)')
            INV.parent.mkdir(parents=True, exist_ok=True)
            save(inv)
            print(f'loaded {file}: log in again (restart the game) to see it')
        case ['reset']:
            INV.unlink(missing_ok=True)
            print('reset: the next inventory.php serves the starting inventory again')
        case ['accounts']:
            for a in accounts().values():
                print(a['email'], a['id'], a['DisplayName'])
        case _:
            raise SystemExit(__doc__)


def selftest():
    global INV, ACCOUNTS, SEED
    tmp = pathlib.Path(tempfile.mkdtemp())
    INV, ACCOUNTS, SEED = tmp / 'inventory.json', tmp / 'accounts.json', tmp / 'seed.json'
    new = load(tmp / 'new.json')  # no seed.json: a fresh account, tutorial first
    assert new['Quests'] == new['Suits'] == new['Melee'] == [] and new['ReceivedStartingGear'] is False
    assert not {'m', 's'} & set(new['LoadOutPresets']['NORMAL'][0]) and new['CurrentLoadOutIds']
    main(['load', str(FIXTURE)])  # the alt's inventory, past the tutorial
    assert load()['Suits'] and load()['ReceivedStartingGear']
    INV.unlink()
    SEED = FIXTURE  # the rest starts from the alt's inventory, as data/seed.json would
    save({'Mine': 1})  # an inventory from before accounts: the first account takes it over
    a = login('Me@Example.com', 'pw')
    assert a and a['DisplayName'] == 'me' and load(inventory_path(a)) == {'Mine': 1} and not INV.exists()
    assert login('me@example.com', 'wrong') is None and login('', 'x') is None
    a2 = login('me@example.com', 'pw')
    assert a2['id'] == a['id'] and session(a['id'], str(a['Nonce'])) is None  # a new login retires the old nonce
    assert session(a['id'], str(a2['Nonce']))['email'] == 'me@example.com'
    assert a2['Nonce'] < 2**31 and len(a2['Token']) == 80 and a2['Token'].isdigit()  # as the client expects
    b = login('friend@example.com', 'x')
    assert b['id'] != a['id'] and 'Suits' in load(inventory_path(b))  # a new player starts from the seed
    try:
        main(['show'])
        raise AssertionError('show picked an account on its own')
    except SystemExit as e:
        assert '2 accounts' in str(e)
    ACCOUNTS = tmp / 'none.json'  # the rest tests the inventory itself, at INV
    main(['give', 'MiscItems', '/Test/Thing', '2'])
    main(['give', 'MiscItems', '/Test/Thing', '3'])
    main(['set', 'RegularCredits', '7'])
    inv = load()
    assert [i['ItemCount'] for i in inv['MiscItems'] if i['ItemType'] == '/Test/Thing'] == [5]
    assert inv['RegularCredits'] == 7 and inv['Suits'] == json.loads(SEED.read_text(encoding='utf-8'))['Suits']
    vendor = {'TypeName': 'V', 'ItemManifest': [
        {'StoreItem': '/SF/StoreItems/Types/Items/Consumables/Pot', 'RegularPrice': [200, 200], 'QuantityMultiplier': 1,
         'Id': {'$oid': 'a1'}, 'Expiry': {'$date': {'$numberLong': str(vendor_rules.FAR)}}, 'PurchaseQuantityLimit': 3}]}
    inv = load()
    suit = inv['Suits'][0]['ItemId']['$oid']
    before = (inv['RegularCredits'], inv['Suits'][0]['XP'])
    r = purchase(inv, {'PurchaseParams': {'StoreItem': '/SF/StoreItems/Types/Items/Consumables/Pot', 'Quantity': 2,
                                          'ExtraPurchaseInfoJson': '{"ItemId":"a1"}'}}, vendor)
    hist = {'Expiry': {'$date': {'$numberLong': str(vendor_rules.FAR)}}, 'ItemId': 'a1', 'NumPurchased': 2}
    assert r == {'InventoryChanges': {'Consumables': [{'ItemType': '/SF/Types/Items/Consumables/Pot', 'ItemCount': 2}],
                                      'RegularCredits': -400,
                                      'NewVendorPurchase': {'VendorType': 'V', 'PurchaseHistory': [hist]}}}, r
    over = {'PurchaseParams': {'StoreItem': '/SF/StoreItems/Types/Items/Consumables/Pot', 'Quantity': 2,
                               'ExtraPurchaseInfoJson': '{"ItemId":"a1"}'}}
    assert purchase(inv, over, vendor) == {'InventoryChanges': {}}  # 2 + 2 > limit 3: refused, nothing charged
    assert [v for v in inv['RecentVendorPurchases'] if v['VendorType'] == 'V'] == [{'PurchaseHistory': [hist], 'VendorType': 'V'}]
    mission_inventory_update(inv, {'RegularCredits': 50, 'MiscItems': [{'ItemType': '/Test/Thing', 'ItemCount': 1}],
                                   'Suits': [{'ItemId': {'$oid': suit}, 'XP': 100}], 'WorldSpawnPosition': [1, 2, 3]})
    challenge_progress(inv, {'ChallengeProgress': [{'Name': 'X', 'Progress': 1}]})
    challenge_progress(inv, {'ChallengeProgress': [{'Name': 'X', 'Progress': 2}]})
    assert (inv['RegularCredits'], inv['Suits'][0]['XP']) == (before[0] - 350, before[1] + 100)
    assert [i['ItemCount'] for i in inv['MiscItems'] if i['ItemType'] == '/Test/Thing'] == [6]
    assert inv['WorldSpawnPosition'] == [1, 2, 3]
    assert [c for c in inv['ChallengeProgress'] if c['Name'] == 'X'] == [{'Name': 'X', 'Progress': 2}]
    if vendor_rules.PACKAGES.exists():  # bodies as in box run 20261029T181616
        bp, seed_type = '/SF/Types/Recipes/Holiday/BirdFeederBlueprint', '/SF/Types/PickUps/Resources/Holiday/VerminiaWinterBirdSeed'
        iron = lambda: sum(i['ItemCount'] for i in inv['MiscItems'] if i['ItemType'].endswith('/ScrapIronResource'))
        give(inv, 'MiscItems', '/SF/Types/PickUps/Resources/ScrapMetals/ScrapIronResource', 20)
        before = (iron(), inv['RegularCredits'])
        rid = start_recipe(inv, {'RecipeName': bp, 'Ids': ['', '', '']})['RecipeId']
        assert (iron(), inv['RegularCredits']) == (before[0] - 15, before[1] - 500)
        r = claim_completed_recipe(inv, {'RecipeIds': [rid], 'Ancestor': ''})
        assert r == {'InventoryChanges': {'MiscItems': [{'ItemType': seed_type, 'ItemCount': 1}]}}, r
        assert claim_completed_recipe(inv, {'RecipeIds': [rid]}) == {'InventoryChanges': {}}  # the client retries
        # A timed weapon craft, rushed, then dismantled (box run 20261029T190809: requests 335, 470, 424).
        bp = '/SF/Types/Recipes/Weapons/SinecureBowRangedMeleeWeaponBlueprint'
        give(inv, 'Recipes', bp, 1)
        rid = start_recipe(inv, {'RecipeName': bp, 'Ids': ['', '', ''], 'Types': ['', '', ''],
                                 'Category': ['', '', ''], 'BonusTier': 0, 'OptionalSelection': ''})['RecipeId']
        claim = {'RecipeIds': [rid], 'Ancestor': '/SF/Types/Game/Ancestors/Tuvalkane/TuvalkaneAncestor'}
        assert claim_completed_recipe(inv, claim) == {'InventoryChanges': {}}  # 20 h build, not rushed: stays pending
        premium = inv.get('PremiumCredits', 0)
        r = claim_completed_recipe(inv, claim | {'_query': {'rush': '1'}})['InventoryChanges']
        assert r['PremiumCredits'] == -15 and inv['PremiumCredits'] == premium - 15, r
        (bow,) = r['Melee']
        assert (bow['ItemType'], bow['Quality'], bow['AspectType']) == (
            '/SF/Weapons/Ranged/TwoHand/SinecureBow/SinecureBowRangedMeleeWeapon', 'IQ_OFFICER',
            '/SF/Types/Items/Aspects/Ranged/OdeRangedAspectManifest'), bow
        assert 2 <= len(bow['AspectFingerprint']['buffs']) <= 4 and bow['AspectFingerprint']['curses'] == []
        assert bow in inv['Melee'] and rid['$oid'] not in str(inv['PendingRecipes'])
        assert (rush_cost(15, 72000, 72000), rush_cost(15, 72000, 1)) == (15, 8)
        r = sell(inv, {'Items': {'Melee': [{'String': bow['ItemId']['$oid'], 'Count': 1}]}, 'SellPrice': 0,
                       'SellCurrency': 'SC_Dismantle', 'buildLabel': 'x'})
        loot = r['inventoryChanges']['MiscItems']
        assert bow not in inv['Melee'] and loot and all(vendor_rules.packages().get(i['ItemType']) for i in loot), loot
        credits = inv['RegularCredits']
        sell(inv, {'Items': {'Melee': [{'String': inv['Melee'][0]['ItemId']['$oid'], 'Count': 1}]}, 'SellPrice': 75,
                   'SellCurrency': 'SC_RegularCredits'})
        assert inv['RegularCredits'] == credits + 75
        try:
            start_recipe(inv, {'RecipeName': '/SF/Types/Recipes/Nope'})
            raise AssertionError('unknown recipe accepted')
        except ValueError:
            pass
    mission_inventory_update(inv, {'Upgrades': [{'ItemType': '/T/Rune', 'ItemId': {'$oid': '0' * 24}, 'ItemCount': 1,
                                                 'UpgradeFingerprint': '{"lvl":1}'}]})
    assert [u['UpgradeFingerprint'] for u in inv['Upgrades'] if u['ItemType'] == '/T/Rune'] == ['{"lvl":1}']
    save_loadout(inv, {'Suits': {suit: {'1': {'Skins': ['a'], 'pricol': {}, 'Songs': []}}}, 'LoadOuts': {}})
    assert inv['Suits'][0]['Configs'][1] == {'Skins': ['a']}
    if vendor_rules.PACKAGES.exists():
        selftest_tutorial(inv)
    main(['reset'])
    assert not INV.exists()
    print('selftest ok')


def selftest_tutorial(inv):
    """The quest graph (TCDemoQuest, as live 20261028T182107549Z), starting gear and the F9 panel's devCheats."""
    tc = '/SF/Types/Quests/TCDemoQuest'
    inv['Quests'] = [q for q in inv['Quests'] if q['ItemType'] != tc]
    q = lambda r: r['InventoryChanges']['Quests'][0]
    assert q(quest_control(inv, {'QuestName': tc, '_query': {'action': 'startWithoutPrereqs'}}))['Progress']['Current'] == ['A99pEAff', 'UY9Y1Vjg']
    r = quest_control(inv, {'Quest': tc, 'Task': 'UY9Y1Vjg', '_query': {'action': 'completeTask'}})
    assert q(r)['Progress']['Current'] == ['A99pEAff', 'Gv7irVfi'], r  # the live answer
    r = quest_control(inv, {'Quest': tc, 'Task': 'HealTutorial', '_query': {'action': 'completeTask'}})  # by Tag
    assert q(r)['Progress']['Current'] == ['Gv7irVfi'], r  # the live answer
    helm = lambda: sum(r['ItemCount'] for r in inv['Recipes'] if r['ItemType'].endswith('/GarrenHelmBlueprint'))
    blueprints = helm()
    for task in ('Gv7irVfi', 'QuCJITh2', 'CG+T346s', 'MghBUzh8', 'XTTcxcg/', 'ckz2u+Zo', '/4FBXhPT', 'tVnZbpBm'):
        r = quest_control(inv, {'Quest': tc, 'Task': task, '_query': {'action': 'completeTask'}})
    assert q(r)['Completed'] == 'YNC0XIhL' and 'Progress' not in q(r), r
    assert helm() == blueprints + 1  # one of the stag fight's rewards
    fresh_inv = fresh(json.loads(FIXTURE.read_text(encoding='utf-8')))
    r = give_starting_gear(fresh_inv, {'Suit': '/SF/Souls/Default/ChampionSoul', 'Skins': [
        '/SF/Upgrades/Skins/Body/StarterCourageBody'], 'Weapon': '/SF/Weapons/Melee/OneHand/StarterSword/StarterSwordMeleeWeapon'})
    assert [s['ItemType'] for s in fresh_inv['Suits']] == ['/SF/Souls/Default/ChampionSoul'] and 'ItemId' in fresh_inv['Suits'][0]
    assert fresh_inv['Melee'][0]['Quality'] == 'IQ_MILITARY' and fresh_inv['WeaponSkins'] and fresh_inv['ReceivedStartingGear']
    sword = '/SF/Weapons/Melee/OneHand/BromiusCleaver/BromiusCleaverMeleeWeapon'
    r = dev_cheats(fresh_inv, {'_query': {'AddItem': sword, 'Count': '2', 'Quality': 'IQ_NOBLE', 'Credits': '500'}})
    assert [m['Quality'] for m in r['InventoryChanges']['Melee']] == ['IQ_NOBLE'] * 2 and fresh_inv['RegularCredits'] == 500, r
    dev_cheats(fresh_inv, {'_query': {'AddItem': '/SF/Types/Items/Consumables/HealingPotion', 'Count': '3'}})
    assert fresh_inv['Consumables'] == [{'ItemCount': 3, 'ItemType': '/SF/Types/Items/Consumables/HealingPotion'}]
    iron = '/SF/Types/PickUps/Resources/ScrapMetals/ScrapIronResource'
    dev_cheats(fresh_inv, {'_query': {'AddItem': iron, 'Count': '40'}})
    assert fresh_inv['MiscItems'] == [{'ItemCount': 40, 'ItemType': iron}]


if __name__ == '__main__':
    selftest() if sys.argv[1:] == ['--selftest'] else main(sys.argv[1:])
