"""Dev tools window for the box: buttons for dev/dev.lua (findings/0032). Double-click, or: pythonw tools/devgui.pyw
The same buttons are now in the game itself (F9, SF dev panel, findings/0033); this window still works alongside it.

Each button compiles one command (tools/devlua.py) and brings the game to the front, because the game only picks up
dev.luac while it is focused. Commands queue: the next one is sent once the previous answer shows up in
sf-bootstrap.log, since a newer dev.luac would replace one the game hasn't run yet.
"""
import ctypes, glob, os, sys, time
import tkinter as tk
from ctypes import wintypes
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import devlua  # noqa: E402

# Where the game writes sf-bootstrap.log: in the Sandboxie box, or in the sf-launch copy setup.cmd made.
LOGS = [os.path.join(os.environ.get('SystemDrive', 'C:') + '\\', 'Sandbox', os.environ.get('USERNAME', '*'),
                     'Soulframe*', 'user', 'current', 'AppData', 'Local', 'Soulframe', 'sf-bootstrap.log'),
        os.path.join(devlua.COPY, 'sf-appdata', 'Local', 'Soulframe', 'sf-bootstrap.log')]
ANSWER_TIMEOUT = 15.0  # seconds before a command counts as unanswered and the queue moves on
GAME_EXE = 'soulframe.x64.exe'

user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32


def log_path() -> str | None:
    found = [p for pattern in LOGS for p in glob.glob(pattern)]
    return max(found, key=os.path.getmtime) if found else None


def game_window() -> int | None:
    """The visible top-level window of Soulframe.x64.exe, found by process name (Sandboxie may change the title)."""
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(hwnd, _):
        if not user32.IsWindowVisible(hwnd):
            return True
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        process = kernel32.OpenProcess(0x1000, False, pid.value)  # PROCESS_QUERY_LIMITED_INFORMATION
        if process:
            name, size = ctypes.create_unicode_buffer(1024), wintypes.DWORD(1024)
            if kernel32.QueryFullProcessImageNameW(process, 0, name, ctypes.byref(size)) and \
                    name.value.lower().endswith('\\' + GAME_EXE):
                found.append(hwnd)
            kernel32.CloseHandle(process)
        return not found

    user32.EnumWindows(each, 0)
    return found[0] if found else None


class DevGui:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.queue: list[str] = []
        self.waiting: tuple[str, int, float] | None = None  # command, log offset when sent, time sent
        self.enemies = {p.rsplit('/', 1)[-1]: p for p in devlua.enemy_types()}
        root.title('SF dev tools')
        root.attributes('-topmost', True)
        pad = {'padx': 4, 'pady': 3}

        spawn = ttk.LabelFrame(root, text='Spawn')
        spawn.pack(fill='x', **pad)
        self.enemy = ttk.Combobox(spawn, values=sorted(self.enemies), width=42)
        self.enemy.set('MeleeGruntAgent')
        self.enemy.bind('<KeyRelease>', self.filter_enemies)
        self.enemy.grid(row=0, column=0, columnspan=4, sticky='we', **pad)
        self.count, self.level = tk.IntVar(value=1), tk.IntVar(value=1)
        ttk.Label(spawn, text='count').grid(row=1, column=0, sticky='e')
        ttk.Spinbox(spawn, from_=1, to=20, width=4, textvariable=self.count).grid(row=1, column=1, sticky='w', **pad)
        ttk.Label(spawn, text='level').grid(row=1, column=2, sticky='e')
        ttk.Spinbox(spawn, from_=1, to=60, width=4, textvariable=self.level).grid(row=1, column=3, sticky='w', **pad)
        ttk.Button(spawn, text='Spawn', command=self.spawn).grid(row=2, column=0, columnspan=2, sticky='we', **pad)
        ttk.Button(spawn, text='Remove spawned', command=lambda: self.send('clear()')).grid(
            row=2, column=2, columnspan=2, sticky='we', **pad)

        toggles = ttk.LabelFrame(root, text='AI and player')
        toggles.pack(fill='x', **pad)
        for col, (text, command) in enumerate([('Freeze AI (50 m)', 'freeze()'), ('Unfreeze', 'freeze(false)'),
                                               ('God on', 'god()'), ('God off', 'god(false)')]):
            ttk.Button(toggles, text=text, command=lambda c=command: self.send(c)).grid(
                row=col // 2, column=col % 2, sticky='we', **pad)
        toggles.columnconfigure((0, 1), weight=1)

        clock = ttk.LabelFrame(root, text='Time of day')
        clock.pack(fill='x', **pad)
        self.hour = tk.IntVar(value=12)
        ttk.Scale(clock, from_=0, to=23, variable=self.hour, command=lambda v: self.hour.set(round(float(v)))).pack(
            side='left', fill='x', expand=True, **pad)
        ttk.Label(clock, textvariable=self.hour, width=3).pack(side='left')
        ttk.Button(clock, text='Set + hold', command=lambda: self.send(f'time({self.hour.get()})')).pack(side='left', **pad)
        ttk.Button(clock, text='Let run', command=lambda: self.send('time()')).pack(side='left', **pad)

        free = ttk.LabelFrame(root, text='Lua expression (dev.lua locals are in scope)')
        free.pack(fill='x', **pad)
        self.expression = ttk.Entry(free)
        self.expression.pack(side='left', fill='x', expand=True, **pad)
        self.expression.bind('<Return>', lambda _: self.send(self.expression.get()))
        ttk.Button(free, text='Run', command=lambda: self.send(self.expression.get())).pack(side='left', **pad)

        self.output = tk.Text(root, height=10, width=60, state='disabled', wrap='word')
        self.output.pack(fill='both', expand=True, **pad)
        self.status = tk.StringVar()
        ttk.Label(root, textvariable=self.status).pack(fill='x', **pad)
        self.say(f'{len(self.enemies)} enemy types. Log: {log_path() or "not found yet (start the game in the box)"}')
        self.tick()

    def filter_enemies(self, _event) -> None:
        text = self.enemy.get().lower()
        self.enemy['values'] = sorted(n for n in self.enemies if text in n.lower())

    def spawn(self) -> None:
        name = self.enemy.get().strip()
        path = self.enemies.get(name, name)  # a name from the list, or anything spawn() accepts
        self.send(f'spawn("{path}", {self.count.get()}, {self.level.get()})')

    def send(self, command: str) -> None:
        if command.strip():
            self.queue.append(command.strip())

    def say(self, line: str) -> None:
        self.output.configure(state='normal')
        self.output.insert('end', line + '\n')
        self.output.see('end')
        self.output.configure(state='disabled')

    def tick(self) -> None:
        try:
            self.step()
        finally:
            self.root.after(150, self.tick)

    def step(self) -> None:
        log = log_path()
        if self.waiting:
            command, offset, sent = self.waiting
            answers = self.read_answers(log, offset)
            if answers:
                for line in answers:
                    self.say('  ' + line)
                self.waiting = None
            elif time.monotonic() - sent > ANSWER_TIMEOUT:
                self.say('  no answer: is the game running, in the world, and focused?')
                self.waiting = None
            else:
                self.status.set(f'waiting for the game: {command}')
                return
        self.status.set(f'{len(self.queue)} queued' if self.queue else 'ready')
        if not self.queue:
            return
        command = self.queue.pop(0)
        self.say('> ' + command)
        try:
            devlua.build(command)
        except ValueError as e:
            self.say('  compile error: ' + str(e).strip())
            return
        self.waiting = (command, os.path.getsize(log) if log else 0, time.monotonic())
        window = game_window()
        if window:
            user32.SetForegroundWindow(window)

    @staticmethod
    def read_answers(log: str | None, offset: int) -> list[str]:
        """dev.lua results written to the log since `offset` (ran / failed / yielded)."""
        if not log or os.path.getsize(log) <= offset:
            return []
        with open(log, 'rb') as f:
            f.seek(offset)
            lines = f.read().decode('utf-8', errors='replace').splitlines()
        return [line.split(' dev: ', 1)[1] for line in lines if ' dev: dev.lua ' in line or ' dev: load failed' in line]


if __name__ == '__main__':
    root = tk.Tk()
    DevGui(root)
    root.mainloop()
