"""Run a command from dev/dev.lua in the box: it runs on the game's next frame (findings/0031, 0032).

    python tools/devlua.py                          # just (re)load the library
    python tools/devlua.py "spawn('MeleeGruntAgent', 3)"
    python tools/devlua.py "enemies('Grunt')"

The command is an expression compiled into the same chunk as dev.lua, so it sees the library's local functions;
its value (or the error) is logged to sf-bootstrap.log as a `dev:` line. The enemy type list comes from the decompiled
BossFightTester in the rust workspace when it's there, else from gamedata/enemy_types.json (the same list); the
item lists of the panel's Items tab come from gamedata/packages.json.gz. play.cmd runs this before every game start.
Upstream luau-compile 0.712 (v6) -> stock_to_game.py (opcode permutation, atoms) -> dev.luac next to the
sf_bootstrap.dll the game loads: %USERPROFILE%\\SoulframePrivate (setup.cmd) if set up, else bootstrap/target/release.
"""
import json, os, re, subprocess, sys, tempfile
import stock_to_game  # tools/stock_to_game.py
import vendor  # tools/vendor.py: package data

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.join(HERE, '..', '..', 'soulframe-rust-workspace')
# tools/luau: the official 0.712 build that setup.ps1 downloads; the workspace's own build of the same tag otherwise.
COMPILER = next((p for p in (os.path.join(HERE, 'luau', 'luau-compile.exe'),
                             os.path.join(WORKSPACE, 'target', 'x', 'b7', 'Release', 'luau-compile.exe')) if os.path.exists(p)),
                os.path.join(HERE, 'luau', 'luau-compile.exe'))
TESTER = os.path.join(WORKSPACE, 'target', 'x', 'corpus', 'out', 'SF', 'Scripts', 'Bosses', 'BossFightTester.lua')
ENEMIES = os.path.join(HERE, '..', 'gamedata', 'enemy_types.json')
LIBRARY = os.path.join(HERE, '..', 'dev', 'dev.lua')
COPY = os.environ.get('SF_COPY') or os.path.join(os.environ.get('USERPROFILE', ''), 'SoulframePrivate')  # SF_COPY: server_gui.pyw
OUT = os.path.join(COPY if os.path.exists(os.path.join(COPY, 'sf_bootstrap.dll')) else
                   os.path.join(HERE, '..', 'bootstrap', 'target', 'release'), 'dev.luac')
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)  # no console flash when the GUI (devgui.pyw) compiles


def enemy_types() -> list[str]:
    try:
        text = open(TESTER, encoding='utf-8').read()
    except OSError:
        return json.load(open(ENEMIES, encoding='utf-8'))
    return list(dict.fromkeys(re.findall(r'enemyType = WeakResource\("([^"]+)"\)', text)))


# The Items tab: title, store item categories (ProductCategory). Base types (/Types/Game/) can't be owned.
ITEM_LISTS = [('Weapons', ('Melee', 'LongGuns')), ('Armour & skins', ('WeaponSkins',)), ('Souls', ('Suits',)),
              ('Consumables', ('Consumables',)), ('Blueprints', ('Recipes',)), ('Runes & skills', ('Upgrades',))]


def items() -> list[tuple[str, list[str]]]:
    p = vendor.packages()
    lists = [(title, sorted(k for k, v in p.items() if k.startswith('/SF/StoreItems/') and '/Types/Game/' not in k
                            and 'TypeName' in v['attributes'] and v['attributes'].get('ProductCategory') in cats))
             for title, cats in ITEM_LISTS]
    # Resources have no store item: the server stacks the type itself (admin.py dev_cheats).
    resources = sorted(k for k, v in p.items() if k.startswith('/SF/Types/PickUps/Resources/') and '/Bundles/' not in k
                       and 'LocalizeTag' in v['attributes'])
    return lists[:1] + [('Resources', resources)] + lists[1:]


def lua_list(paths: list[str]) -> str:
    return '{' + ', '.join(f'"{p}"' for p in paths) + '}'


def source(command: str) -> str:
    # Prepended on line 1 (dev.lua starts with a comment), so error line numbers still match dev.lua.
    enemies = f'local sfdev_enemies = {lua_list(enemy_types())} '
    # In a function of its own: ~1100 constants in the main chunk push its imports (string.match) past GETIMPORT's
    # 1024-constant reach, and they'd compile to the field reads check_fields refuses.
    lists = ', '.join(f'{{"{t}", {lua_list(ps)}}}' for t, ps in items())
    enemies += f'local sfdev_items = (function() return {{{lists}}} end)() '
    # `frame` first: sf_bootstrap.dll keeps it and calls it every frame while the overlay is shown (findings/0033); the
    # command's value is on top, which is what gets logged. pcall, so a failing command doesn't take the panel down.
    command = command or '"dev library loaded"'
    tail = f'\nreturn frame, run(function() return ({command}) end)\n'
    return enemies + open(LIBRARY, encoding='utf-8').read() + tail


def check_fields(stock: bytes, known: set[int]) -> None:
    """Refuse `t.field` / `t.field = x` whose name stock_to_game would turn into an atom (an `a_XXXXXXXX` name, or one
    the game's scripts use as an atom, e.g. `level`, `name`). The VM reads that constant as a string pointer, so an
    atom there crashes the game (findings/0033, box run 2026-10-30 13:19). Method calls (`obj:a_XXXXXXXX()`) are fine."""
    s, upcodes = stock_to_game, stock_to_game.L.UP
    strings, _, protos, _ = s.parse(stock, game=False)
    bad = set()
    for p in protos:
        use = s.usage(p)
        for i, name, _ in s.walk(p['code'], lambda op: upcodes[op]):
            if name not in ('GETTABLEKS', 'SETTABLEKS'):
                continue
            k = p['code'][i + 1]
            tag, v = p['k'][k]
            how = use.get(k, set())
            text = strings[v - 1].decode(errors='replace') if tag == 3 else ''
            if tag == 3 and 'value' not in how and ('method' in how or s.UNNAMED.match(strings[v - 1])
                                                    or s.atom(strings[v - 1]) in known):
                bad.add(text)
    if bad:
        raise ValueError(f'field name(s) {", ".join(sorted(bad))} would compile to game atoms and crash the game; '
                         'rename them (see dev.lua, "Our own tables")')


# Globals that are really strings in _G: ours. Every other global the game has is keyed by atom.
STRING_GLOBALS = {'sfdev'}


def check_globals(stock: bytes, known: set[int]) -> None:
    """Refuse a global whose name compiles to a string: the game keys its globals by atom, so that's nil in game.
    engine_atoms.json has guessed names that hash to nothing (RotationToDirection is a_e97f3142, box run 2026-10-30);
    use the a_XXXXXXXX name for those."""
    s, upcodes = stock_to_game, stock_to_game.L.UP
    strings, _, protos, _ = s.parse(stock, game=False)
    bad = set()
    for p in protos:
        for i, name, w in s.walk(p['code'], lambda op: upcodes[op]):
            if name == 'GETIMPORT':
                v = p['k'][w >> 16][1]
                k = (v >> 20) & 1023  # the first name of a.b.c
            elif name in ('GETGLOBAL', 'SETGLOBAL'):
                k = p['code'][i + 1]
            else:
                continue
            text = strings[p['k'][k][1] - 1]
            if text.decode(errors='replace') not in STRING_GLOBALS and not s.UNNAMED.match(text) and s.atom(text) not in known:
                bad.add(text.decode(errors='replace'))
    if bad:
        raise ValueError(f'global(s) {", ".join(sorted(bad))} are not names the game has (they would be nil); use the '
                         'a_XXXXXXXX atom, or a local if it is your own')


def native_atoms() -> set[int]:
    """The ImGui natives sf_bootstrap.dll installs. The VM keys them by atom, but known_atoms() only has the names the
    game's scripts use, so one they never call (ImGuiTextWrapped) compiled to a string global, which is nil in game."""
    text = open(os.path.join(HERE, '..', 'bootstrap', 'src', 'imgui.rs'), encoding='utf-8').read()
    return {int(atom.replace('_', ''), 16) for atom in re.findall(r'\(0x([0-9a-f_]+), "ImGui\w+"', text)}


def build(command: str) -> int:
    """Compile dev.lua + command into dev.luac; returns its size, raises ValueError with the compiler's message."""
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, 'dev.lua')
        open(src, 'w', encoding='utf-8').write(source(command))
        run = subprocess.run([COMPILER, '--binary', src], capture_output=True, creationflags=NO_WINDOW)
    if run.returncode:
        raise ValueError(run.stdout.decode(errors='replace') + run.stderr.decode(errors='replace'))
    known = stock_to_game.known_atoms() | native_atoms()
    check_fields(run.stdout, known)
    check_globals(run.stdout, known)
    game = stock_to_game.to_game(run.stdout, known)
    # Write then rename, so the game never reads half a file.
    open(OUT + '.tmp', 'wb').write(game)
    os.replace(OUT + '.tmp', OUT)
    return len(game)


def main() -> None:
    try:
        size = build(' '.join(sys.argv[1:]))
    except ValueError as e:
        sys.exit(str(e))
    print(f'{os.path.normpath(OUT)}: {size} bytes')


if __name__ == '__main__':
    main()
