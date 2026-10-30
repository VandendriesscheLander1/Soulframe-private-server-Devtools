//! sf-bootstrap.dll: loaded only into Sandboxie box `SoulframeP16H6` (`InjectDll64=`, see tools\play.ps1).
//! Inside that process it sends every *.soulframe.com lookup to 127.0.0.1 and turns off certificate
//! checks for both TLS stacks, and makes the EZIP body key all zeros so our server can decrypt request bodies
//! (findings/0017). The hosts file and the machine cert store stay untouched, so the live game
//! keeps working at the same time (findings/0013). Dev keys: F7 free camera, F8 teleport to the free camera (or blink 20 m along the view) (findings/0025).
//! dev.luac next to this DLL (tools\devlua.py) runs in the game's script VM whenever it changes (findings/0031); the
//! function it returns runs every frame while the ImGui overlay (F9) is shown. The overlay draws the devs' own ImGui
//! panels: our natives replace the retail no-op ImGui* ones (imgui.rs, findings/0033).
//! Refuses to hook anything unless the exe is build P16H6. Logs to %LOCALAPPDATA%\Soulframe\sf-bootstrap.log
//! (inside the sandbox: next to EE.log).
//! Phase 6: the server address comes from sf-server.txt next to this DLL (default 127.0.0.1), so players can join
//! someone else's server. Without Sandboxie, sf-launch.exe starts the game with LOCALAPPDATA/APPDATA pointing into
//! the game copy; SHGetFolderPathW answers from those too, so nothing reaches the live game's AppData. Once every
//! hook is in, the DLL signals sf-launch, which only then lets the game run.

mod imgui;
mod live;

use retour::RawDetour;
use std::ffi::{c_char, c_void, CStr};
use std::io::Write;
use std::sync::{Mutex, OnceLock};

// P16H6 (findings/0001): PE header values plus the first bytes of the statically linked curl_easy_setopt.
const PIN_TIMESTAMP: u32 = 0x6ac7_ed24;
const PIN_SIZE_OF_IMAGE: u32 = 0x02ca_9000;
const SETOPT_RVA: usize = 0x01db_5a50;
// mov [rsp+10],edx; mov [rsp+18],r8; mov [rsp+20],r9; sub rsp,28; test rcx,rcx
const SETOPT_PROLOGUE: [u8; 21] = [
    0x89, 0x54, 0x24, 0x10, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x4c, 0x89, 0x4c, 0x24, 0x20, 0x48, 0x83, 0xec,
    0x28, 0x48, 0x85, 0xc9,
];

// EZIP writer constructor (findings/0017): draws an AES-192-CBC key+iv with RAND_bytes and RSA-wraps it with
// DE's public key. While it runs, RAND_bytes hands out zeros, so the server can decrypt with a zero key/iv.
const EZIP_INIT_RVA: usize = 0x00cd_4400;
const EZIP_INIT_PROLOGUE: [u8; 14] = [0x40, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x60];
const RAND_BYTES_RVA: usize = 0x01ca_5210; // OpenSSL RAND_bytes(buf, num)
const RAND_BYTES_PROLOGUE: [u8; 15] = [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x30, 0x8b, 0xda, 0x48, 0x8b, 0xf9];

// NetDriver packet compressor (findings/0028): (ctx, packet TArray, mode). Keeps the compressed form only when smaller,
// else prefixes 0x00. Mode 0 = always raw, so our hub relay (tools/hub_relay.py) never has to decompress a client's
// loadout. Only NetDriver sends call it.
// UNFINISHED, OFF: the hub relay is parked (tools/dummy_server.py --hub), and this hook was never tested in a box run.
// While false the hook just passes the game's own mode through. Set to true together with --hub.
const HUB_RAW_PACKETS: bool = false;
const COMPRESS_PACKET_RVA: usize = 0x00dd_3720;
const COMPRESS_PACKET_PROLOGUE: [u8; 16] =
    [0x40, 0x55, 0x56, 0x57, 0x48, 0x83, 0xec, 0x70, 0x48, 0x8b, 0x05, 0x51, 0x5f, 0xa8, 0x01, 0x48];

// Dev tools (findings/0025). Retail stubs the editor commands, so we call the engine functions behind them.
// SFHumanPlayer's per-frame input update runs on the game thread with the player in hand; hotkeys are polled there.
// (The generic input-action handler at 0x171b00 never ran for the Soulframe player.)
const PLAYER_UPDATE_RVA: usize = 0x00b0_8960; // (player, dt, input)
const PLAYER_UPDATE_PROLOGUE: [u8; 15] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x50];
const TOGGLE_FREE_CAMERA_RVA: usize = 0x0073_7c80; // SFHumanPlayer free camera, what photo mode's G key calls
const TOGGLE_FREE_CAMERA_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x80, 0xb9, 0x58, 0x01, 0x00, 0x00];
const EULER_TO_QUAT_RVA: usize = 0x0179_7bd0; // (out, x, y, z), used by Luau Entity:Teleport
const EULER_TO_QUAT_PROLOGUE: [u8; 16] =
    [0x40, 0x53, 0x48, 0x83, 0xec, 0x50, 0x0f, 0x14, 0xd1, 0x4c, 0x8d, 0x44, 0x24, 0x20, 0x0f, 0x57];
const INVERT_RVA: usize = 0x00cb_99a0; // 4x4 inverse (in, out), used by Luau GetViewPosition
const INVERT_PROLOGUE: [u8; 16] =
    [0x4c, 0x8b, 0xdc, 0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00, 0x0f, 0x10, 0x51, 0x20, 0x41, 0x0f];
const PLAYER_TYPE_RVA: usize = 0x028a_1b50; // SFHumanPlayer, checked before ToggleFreeCamera
const PLAYER_FREE_CAMERA: usize = 0x158; // bool
const PLAYER_AVATAR: usize = 0x148; // **avatar
const PLAYER_CAMERA: usize = 0xd0; // **camera; the base player update reads/writes view angles through it
const PLAYER_FREE_CAMERA_ENTITY: usize = 0x30; // **entity the base update 0x137d720 flies while free camera is on
const CAMERA_VIEW_MATRIX: usize = 0x30; // camera vtable (rva 0x209c0e8) slot 0x108 = lea rax,[rcx+0x30], what GetViewPosition inverts
const ENTITY_TELEPORT_VSLOT: usize = 0x368; // (entity, &pos, &quat)
const ENTITY_POSITION: usize = 0x70; // vec3
const BLINK_DISTANCE: f32 = 20.0; // metres per F8
const VK_F7: i32 = 0x76; // F5 is the game's RESET_INPUT_STATE
const VK_F8: i32 = 0x77;
const VK_F10: i32 = 0x79; // teleport to the map marker (dev.lua does it on the panel's frame)

// The Luau native behind `avatar:a_4ec993ab(x, z[, b[, n]])`, which Map.lua TrySetWaypoint calls when the player places
// the map marker (binding row .rdata 0x220b010). Scripts never read the marker back, so we remember it here and hand
// it to dev.lua's frame function. (0, 0) is how Social.lua clears it.
const SET_MAP_MARKER_RVA: usize = 0x01b2_4b60; // (L) -> 0
const SET_MAP_MARKER_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x60, 0x0f];

// Dev Luau (findings/0030, 0031). The engine's script loader hands its lua_State to LOAD_CHUNK; we keep it, and from the
// player update (game thread) run dev.luac (next to this DLL, built by tools\devlua.py) on a new thread when it changes.
const LOAD_CHUNK_RVA: usize = 0x003b_4830; // (L, chunkname, data, size, env) -> status; pushes the function or an error
const LOAD_CHUNK_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57];
const LUA_RESUME_RVA: usize = 0x0137_5af0; // (L, from, nargs) -> status; "cannot resume non-suspended coroutine"
const LUA_RESUME_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x0f, 0xb6, 0x41, 0x03, 0x48, 0x8b];
const LUA_NEWTHREAD_RVA: usize = 0x016f_a010; // (L) -> thread, pushed on L
const LUA_NEWTHREAD_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0x51, 0x18, 0x48, 0x8b];
const LUA_CHECKSTACK_RVA: usize = 0x0157_5670; // (L, n) -> bool
const LUA_CHECKSTACK_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48];
const LUA_REF_RVA: usize = 0x0089_2890; // (L, idx) -> ref
const LUA_REF_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x41, 0x56, 0x48, 0x83, 0xec, 0x20];
const LUA_SETTOP_RVA: usize = 0x0179_06b0; // (L, idx)
const LUA_SETTOP_PROLOGUE: [u8; 16] =
    [0x85, 0xd2, 0x78, 0x3f, 0x4c, 0x8b, 0x41, 0x10, 0x4c, 0x63, 0xca, 0x48, 0x8b, 0x51, 0x08, 0x4d];
const LUA_PUSHVALUE_RVA: usize = 0x0139_8770; // (L, idx)
const LUA_PUSHVALUE_PROLOGUE: [u8; 16] =
    [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0xf6, 0x41, 0x01, 0x04, 0x48, 0x8b];
// What the engine's script scheduler calls right before each lua_resume (0x119abb6): `mov dword [L+0x88], 0`, the
// count the interrupt handler 0x18fc820 raises "Infinite loop detected" past 800000. Our panel thread is resumed every
// frame without it, so the count only grew and the panel died after a few minutes (box run 2026-10-30).
const LUA_RESET_INTERRUPTS_RVA: usize = 0x016e_ac10; // (L)
const LUA_RESET_INTERRUPTS_PROLOGUE: [u8; 11] = [0xc7, 0x81, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3];
const LUA_STATUS: usize = 0x03; // u8: 0 ok, 1 yielded
const LUA_TOP: usize = 0x08; // lua_State: top TValue*, base at +0x10
const LUA_BASE: usize = 0x10;
const TVALUE_TAG: usize = 0x0c; // TValue is 16 bytes: value, extra, tag (i32)
const TAG_STRING: i32 = 5;
const TAG_FUNCTION: i32 = 7;
const TSTRING_LEN: usize = 0x14; // u32, chars follow at +0x18
const TSTRING_DATA: usize = 0x18;

const CURLOPT_SSL_VERIFYPEER: u32 = 64;
const CURLOPT_SSL_VERIFYHOST: u32 = 81;
const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
// IGNORE_CERT_CN_INVALID | IGNORE_CERT_DATE_INVALID | IGNORE_UNKNOWN_CA | IGNORE_CERT_WRONG_USAGE
const WINHTTP_IGNORE_CERT_ERRORS: u32 = 0x1000 | 0x2000 | 0x100 | 0x200;

const CSIDL_APPDATA: i32 = 0x1a;
const CSIDL_LOCAL_APPDATA: i32 = 0x1c;
const CSIDL_FLAG_CREATE: i32 = 0x8000;
const MAX_PATH: usize = 260;

/// Where *.soulframe.com goes: the first line of sf-server.txt next to this DLL, else 127.0.0.1.
static SERVER: OnceLock<(std::ffi::CString, Vec<u16>)> = OnceLock::new();
static MODULE: std::sync::atomic::AtomicPtr<c_void> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *const u8;
    fn GetModuleFileNameW(module: *const c_void, path: *mut u16, len: u32) -> u32;
    fn GetProcAddress(module: *const u8, name: *const c_char) -> *const c_void;
    fn GetCurrentProcessId() -> u32;
    fn VirtualQuery(at: *const c_void, info: *mut c_void, len: usize) -> usize;
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
    fn SetEvent(event: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}
#[link(name = "user32")]
extern "system" {
    fn GetAsyncKeyState(vk: i32) -> i16;
    fn GetForegroundWindow() -> *mut c_void;
    fn GetWindowThreadProcessId(window: *mut c_void, pid: *mut u32) -> u32;
}
#[link(name = "winhttp")]
extern "system" {
    fn WinHttpSetOption(handle: *mut c_void, option: u32, buffer: *const c_void, len: u32) -> i32;
}

type GetAddrInfoA = unsafe extern "system" fn(*const c_char, *const c_char, *const c_void, *mut c_void) -> i32;
type GetAddrInfoW = unsafe extern "system" fn(*const u16, *const u16, *const c_void, *mut c_void) -> i32;
type GetAddrInfoExW = unsafe extern "system" fn(
    *const u16, *const u16, u32, *const c_void, *const c_void, *mut c_void, *const c_void, *mut c_void,
    *const c_void, *mut c_void,
) -> i32;
type WinHttpSendRequest = unsafe extern "system" fn(*mut c_void, *const u16, u32, *const c_void, u32, u32, usize) -> i32;
type ShGetFolderPathW = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, u32, *mut u16) -> i32;
// Variadic in C, but on Win64 the third argument is in r8 either way.
type CurlEasySetopt = unsafe extern "C" fn(*mut c_void, u32, usize) -> u32;
type EzipInit = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type RandBytes = unsafe extern "C" fn(*mut u8, i32) -> i32;
type PlayerUpdate = unsafe extern "C" fn(*const u8, f32, *const c_void);
type CompressPacket = unsafe extern "C" fn(*mut c_void, *mut c_void, i32) -> usize;
type LoadChunk = unsafe extern "C" fn(*mut u8, *const c_char, *const u8, usize, i32) -> i32;
type LuaNative = unsafe extern "C" fn(*mut u8) -> i32;

#[repr(C, align(16))]
struct Vec4([f32; 4]);
#[repr(C, align(16))]
struct Mat4([f32; 16]);

static GETADDRINFO: OnceLock<RawDetour> = OnceLock::new();
static GETADDRINFOW: OnceLock<RawDetour> = OnceLock::new();
static GETADDRINFOEXW: OnceLock<RawDetour> = OnceLock::new();
static SENDREQUEST: OnceLock<RawDetour> = OnceLock::new();
static SETOPT: OnceLock<RawDetour> = OnceLock::new();
static EZIP_INIT: OnceLock<RawDetour> = OnceLock::new();
static RAND_BYTES: OnceLock<RawDetour> = OnceLock::new();
static PLAYER_UPDATE: OnceLock<RawDetour> = OnceLock::new();
static SHGETFOLDERPATHW: OnceLock<RawDetour> = OnceLock::new();
static COMPRESS_PACKET: OnceLock<RawDetour> = OnceLock::new();
static LOAD_CHUNK: OnceLock<RawDetour> = OnceLock::new();
static SET_MAP_MARKER: OnceLock<RawDetour> = OnceLock::new();
/// The last map marker (x, z), or None.
static MAP_MARKER: Mutex<Option<(f32, f32)>> = Mutex::new(None);
/// F10 was pressed: the next frame-function call teleports to the marker.
static MARKER_TELEPORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The script VM's lua_State, as last passed to the engine's chunk loader.
static LUA: std::sync::atomic::AtomicPtr<u8> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
/// The thread dev.luac last ran on, with the frame function it returned as its only stack value (or null).
static DEV_FRAME: std::sync::atomic::AtomicPtr<u8> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
static EXE:std::sync::atomic::AtomicPtr<u8> = std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());
thread_local!(static IN_EZIP_INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });

#[no_mangle]
extern "system" fn DllMain(module: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        MODULE.store(module, std::sync::atomic::Ordering::Relaxed);
        // ponytail: hooks go in from a thread (no heavy work under the loader lock). It starts as soon as the
        // loader is done, seconds before the first network call. Hook in DllMain if a lookup is ever seen unhooked.
        std::thread::spawn(|| unsafe { init() });
    }
    1
}

unsafe fn init() {
    let exe = GetModuleHandleW(std::ptr::null());
    let mut path = [0u16; 1024];
    let len = GetModuleFileNameW(std::ptr::null(), path.as_mut_ptr(), 1024) as usize;
    let exe_path = String::from_utf16_lossy(&path[..len]);
    if len == 0 || live::is_official_install(&exe_path) {
        log(&format!("{exe_path:?} is a real game install, not a copy; NOT hooking"));
        return;
    }
    if let Err(why) = check_build(exe) {
        log(&format!("unsupported build ({why}); NOT hooking (sf-launch then stops the game; in the box the firewall keeps it offline)"));
        return;
    }
    let (server, _) = SERVER.get_or_init(|| read_server());
    log(&format!("server: {}", server.to_string_lossy()));
    EXE.store(exe.cast_mut(), std::sync::atomic::Ordering::Relaxed); // our natives use it
    // Before the VM exists: it copies the native table once, at setup.
    let natives = imgui::install(exe);
    match &natives {
        Ok(n) => log(&format!("imgui: {n} ImGui natives replaced")),
        Err(e) => log(&format!("imgui: FAILED to replace the ImGui natives: {e}")),
    }
    let ws2 = GetModuleHandleW(wide::<11>("ws2_32.dll").as_ptr());
    let winhttp = GetModuleHandleW(wide::<12>("winhttp.dll").as_ptr());
    let shell32 = GetModuleHandleW(wide::<12>("shell32.dll").as_ptr());
    let hooks: [(&str, &OnceLock<RawDetour>, *const c_void, *const ()); 12] = [
        ("set map marker (F10 teleport)", &SET_MAP_MARKER, exe.add(SET_MAP_MARKER_RVA).cast(), hook_set_map_marker as _),
        ("script chunk loader (dev.luac)", &LOAD_CHUNK, exe.add(LOAD_CHUNK_RVA).cast(), hook_load_chunk as _),
        ("NetDriver compress (raw if HUB_RAW_PACKETS)", &COMPRESS_PACKET, exe.add(COMPRESS_PACKET_RVA).cast(), hook_compress_packet as _),
        ("SHGetFolderPathW", &SHGETFOLDERPATHW, GetProcAddress(shell32, c"SHGetFolderPathW".as_ptr()), hook_shgetfolderpathw as _),
        ("getaddrinfo", &GETADDRINFO, GetProcAddress(ws2, c"getaddrinfo".as_ptr()), hook_getaddrinfo as _),
        ("GetAddrInfoW", &GETADDRINFOW, GetProcAddress(ws2, c"GetAddrInfoW".as_ptr()), hook_getaddrinfow as _),
        ("GetAddrInfoExW", &GETADDRINFOEXW, GetProcAddress(ws2, c"GetAddrInfoExW".as_ptr()), hook_getaddrinfoexw as _),
        ("WinHttpSendRequest", &SENDREQUEST, GetProcAddress(winhttp, c"WinHttpSendRequest".as_ptr()), hook_sendrequest as _),
        ("curl_easy_setopt", &SETOPT, exe.add(SETOPT_RVA).cast(), hook_setopt as _),
        ("EzipInit", &EZIP_INIT, exe.add(EZIP_INIT_RVA).cast(), hook_ezip_init as _),
        ("RAND_bytes", &RAND_BYTES, exe.add(RAND_BYTES_RVA).cast(), hook_rand_bytes as _),
        ("player update (dev keys F7/F8)", &PLAYER_UPDATE, exe.add(PLAYER_UPDATE_RVA).cast(), hook_player_update as _),
    ];
    let mut all = true;
    for (name, slot, target, detour) in hooks {
        let result = if target.is_null() {
            Err("not found".to_string())
        } else {
            RawDetour::new(target.cast(), detour)
                .and_then(|d| slot.get_or_init(|| d).enable())
                .map_err(|e| e.to_string())
        };
        match result {
            Ok(()) => log(&format!("hooked {name}")),
            Err(e) => {
                all = false;
                log(&format!("FAILED to hook {name}: {e}"));
            }
        }
    }
    if natives.is_ok() {
        imgui::start_overlay();
    }
    if all {
        signal_launcher();
    }
}

/// sf-launch.exe holds the game suspended until this event fires (none exists under Sandboxie, so nothing happens).
unsafe fn signal_launcher() {
    const EVENT_MODIFY_STATE: u32 = 2;
    let name: Vec<u16> = format!("Local\\sf-bootstrap-ready-{}\0", GetCurrentProcessId()).encode_utf16().collect();
    let event = OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr());
    if !event.is_null() {
        SetEvent(event);
        CloseHandle(event);
        log("ready: told sf-launch to start the game");
    }
}

unsafe fn beside_dll(name: &str) -> std::path::PathBuf {
    let mut path = [0u16; 1024];
    let len = GetModuleFileNameW(MODULE.load(std::sync::atomic::Ordering::Relaxed), path.as_mut_ptr(), 1024) as usize;
    std::path::PathBuf::from(String::from_utf16_lossy(&path[..len])).with_file_name(name)
}

unsafe fn read_server() -> (std::ffi::CString, Vec<u16>) {
    let file = beside_dll("sf-server.txt");
    let text = std::fs::read_to_string(&file).unwrap_or_default();
    let server = match server_address(&text) {
        Some(s) => s,
        None => {
            if !text.trim().is_empty() {
                log(&format!("{} is not an address or host name; using 127.0.0.1", file.display()));
            }
            "127.0.0.1".to_string()
        }
    };
    let wide = server.encode_utf16().chain([0]).collect();
    (std::ffi::CString::new(server).unwrap_or_default(), wide)
}

/// The first non-comment line, if it's a plain host name or IP (never one we'd redirect again).
fn server_address(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let ok = line.len() <= 253 && line.chars().all(|c| c.is_ascii_alphanumeric() || ".-:".contains(c));
    (ok && !redirected(line)).then(|| line.to_string())
}

/// CSIDL_LOCAL_APPDATA / CSIDL_APPDATA answer from the environment, which sf-launch points into the game copy
/// (under Sandboxie it's the normal value, so nothing changes there).
unsafe extern "system" fn hook_shgetfolderpathw(
    window: *mut c_void, csidl: i32, token: *mut c_void, flags: u32, path: *mut u16,
) -> i32 {
    let var = match csidl & 0xff {
        CSIDL_LOCAL_APPDATA => Some("LOCALAPPDATA"),
        CSIDL_APPDATA => Some("APPDATA"),
        _ => None,
    };
    if let (Some(dir), false) = (var.and_then(std::env::var_os), path.is_null()) {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = dir.encode_wide().chain([0]).collect();
        if wide.len() <= MAX_PATH {
            if csidl & CSIDL_FLAG_CREATE != 0 {
                let _ = std::fs::create_dir_all(&dir);
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), path, wide.len());
            return 0; // S_OK
        }
    }
    let original: ShGetFolderPathW = std::mem::transmute(SHGETFOLDERPATHW.get().unwrap().trampoline());
    original(window, csidl, token, flags, path)
}

unsafe fn check_build(exe: *const u8) -> Result<(), String> {
    let nt = exe.add(exe.add(0x3c).cast::<u32>().read_unaligned() as usize);
    let timestamp = nt.add(8).cast::<u32>().read_unaligned();
    let size = nt.add(0x18 + 56).cast::<u32>().read_unaligned(); // OptionalHeader64.SizeOfImage
    if (timestamp, size) != (PIN_TIMESTAMP, PIN_SIZE_OF_IMAGE) {
        return Err(format!("timestamp {timestamp:#x}, image size {size:#x}"));
    }
    let pinned: [(&str, usize, &[u8]); 20] = [
        ("chunk loader", LOAD_CHUNK_RVA, &LOAD_CHUNK_PROLOGUE),
        ("reset interrupt count", LUA_RESET_INTERRUPTS_RVA, &LUA_RESET_INTERRUPTS_PROLOGUE),
        ("set map marker", SET_MAP_MARKER_RVA, &SET_MAP_MARKER_PROLOGUE),
        ("lua_pushvalue", LUA_PUSHVALUE_RVA, &LUA_PUSHVALUE_PROLOGUE),
        ("lua_pushnil", imgui::LUA_PUSHNIL_RVA, &imgui::LUA_PUSHNIL_PROLOGUE),
        ("lua_next", imgui::LUA_NEXT_RVA, &imgui::LUA_NEXT_PROLOGUE),
        ("push engine string", imgui::PUSH_STRING_RVA, &imgui::PUSH_STRING_PROLOGUE),
        ("lua_resume", LUA_RESUME_RVA, &LUA_RESUME_PROLOGUE),
        ("lua_newthread", LUA_NEWTHREAD_RVA, &LUA_NEWTHREAD_PROLOGUE),
        ("lua_checkstack", LUA_CHECKSTACK_RVA, &LUA_CHECKSTACK_PROLOGUE),
        ("lua_ref", LUA_REF_RVA, &LUA_REF_PROLOGUE),
        ("lua_settop", LUA_SETTOP_RVA, &LUA_SETTOP_PROLOGUE),
        ("NetDriver compress", COMPRESS_PACKET_RVA, &COMPRESS_PACKET_PROLOGUE),
        ("curl_easy_setopt", SETOPT_RVA, &SETOPT_PROLOGUE),
        ("EZIP init", EZIP_INIT_RVA, &EZIP_INIT_PROLOGUE),
        ("RAND_bytes", RAND_BYTES_RVA, &RAND_BYTES_PROLOGUE),
        ("player update", PLAYER_UPDATE_RVA, &PLAYER_UPDATE_PROLOGUE),
        ("ToggleFreeCamera", TOGGLE_FREE_CAMERA_RVA, &TOGGLE_FREE_CAMERA_PROLOGUE),
        ("euler to quat", EULER_TO_QUAT_RVA, &EULER_TO_QUAT_PROLOGUE),
        ("matrix inverse", INVERT_RVA, &INVERT_PROLOGUE),
    ];
    for (name, rva, prologue) in pinned {
        if std::slice::from_raw_parts(exe.add(rva), prologue.len()) != prologue {
            return Err(format!("{name} not at the pinned RVA"));
        }
    }
    Ok(())
}

fn redirected(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "soulframe.com" || host.ends_with(".soulframe.com")
}

unsafe fn host_w(name: *const u16) -> String {
    if name.is_null() {
        return String::new();
    }
    let len = (0..).take_while(|&i| *name.add(i) != 0).count();
    String::from_utf16_lossy(std::slice::from_raw_parts(name, len))
}

/// The name to really look up: our server for our hosts, the original otherwise.
unsafe fn swap_w(name: *const u16, via: &str) -> *const u16 {
    let host = host_w(name);
    if !redirected(&host) {
        return name;
    }
    let (server, server_w) = SERVER.get_or_init(|| read_server());
    log(&format!("{via}: {host} -> {}", server.to_string_lossy()));
    server_w.as_ptr()
}

unsafe extern "system" fn hook_getaddrinfo(node: *const c_char, service: *const c_char, hints: *const c_void, res: *mut c_void) -> i32 {
    let mut node = node;
    if !node.is_null() {
        let host = CStr::from_ptr(node).to_string_lossy();
        if redirected(&host) {
            let (server, _) = SERVER.get_or_init(|| read_server());
            log(&format!("getaddrinfo: {host} -> {}", server.to_string_lossy()));
            node = server.as_ptr();
        }
    }
    let original: GetAddrInfoA = std::mem::transmute(GETADDRINFO.get().unwrap().trampoline());
    original(node, service, hints, res)
}

unsafe extern "system" fn hook_getaddrinfow(node: *const u16, service: *const u16, hints: *const c_void, res: *mut c_void) -> i32 {
    let original: GetAddrInfoW = std::mem::transmute(GETADDRINFOW.get().unwrap().trampoline());
    original(swap_w(node, "GetAddrInfoW"), service, hints, res)
}

#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn hook_getaddrinfoexw(
    name: *const u16, service: *const u16, namespace: u32, nsp_id: *const c_void, hints: *const c_void,
    result: *mut c_void, timeout: *const c_void, overlapped: *mut c_void, completion: *const c_void, handle: *mut c_void,
) -> i32 {
    let original: GetAddrInfoExW = std::mem::transmute(GETADDRINFOEXW.get().unwrap().trampoline());
    let name = swap_w(name, "GetAddrInfoExW");
    original(name, service, namespace, nsp_id, hints, result, timeout, overlapped, completion, handle)
}

unsafe extern "system" fn hook_sendrequest(
    request: *mut c_void, headers: *const u16, headers_len: u32, optional: *const c_void, optional_len: u32,
    total_len: u32, context: usize,
) -> i32 {
    // Fails harmlessly on plain-HTTP requests; nothing to check.
    WinHttpSetOption(request, WINHTTP_OPTION_SECURITY_FLAGS, (&WINHTTP_IGNORE_CERT_ERRORS as *const u32).cast(), 4);
    let original: WinHttpSendRequest = std::mem::transmute(SENDREQUEST.get().unwrap().trampoline());
    original(request, headers, headers_len, optional, optional_len, total_len, context)
}

unsafe extern "C" fn hook_setopt(handle: *mut c_void, option: u32, value: usize) -> u32 {
    let value = match option {
        CURLOPT_SSL_VERIFYPEER | CURLOPT_SSL_VERIFYHOST => {
            log(&format!("curl_easy_setopt({option}, {value}) -> 0"));
            0
        }
        _ => value,
    };
    let original: CurlEasySetopt = std::mem::transmute(SETOPT.get().unwrap().trampoline());
    original(handle, option, value)
}

unsafe extern "C" fn hook_ezip_init(writer: *mut c_void) -> *mut c_void {
    IN_EZIP_INIT.with(|f| f.set(true));
    let original: EzipInit = std::mem::transmute(EZIP_INIT.get().unwrap().trampoline());
    let result = original(writer);
    IN_EZIP_INIT.with(|f| f.set(false));
    result
}

unsafe extern "C" fn hook_rand_bytes(buf: *mut u8, num: i32) -> i32 {
    if IN_EZIP_INIT.with(|f| f.get()) {
        std::ptr::write_bytes(buf, 0, num.max(0) as usize);
        return 1;
    }
    let original: RandBytes = std::mem::transmute(RAND_BYTES.get().unwrap().trampoline());
    original(buf, num)
}

/// With HUB_RAW_PACKETS every NetDriver packet goes out raw (mode 0); the callers ignore the return value (findings/0028).
unsafe extern "C" fn hook_compress_packet(ctx: *mut c_void, packet: *mut c_void, mode: i32) -> usize {
    let original: CompressPacket = std::mem::transmute(COMPRESS_PACKET.get().unwrap().trampoline());
    original(ctx, packet, if HUB_RAW_PACKETS { 0 } else { mode })
}

unsafe extern "C" fn hook_player_update(player: *const u8, dt: f32, input: *const c_void) {
    static FIRST: std::sync::Once = std::sync::Once::new();
    FIRST.call_once(|| log("dev: player update running, F7/F8/F9 live"));
    dev_keys(player);
    if pressed(VK_F10, 3) {
        MARKER_TELEPORT.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    imgui::poll_toggle();
    imgui::publish_frame(); // one game frame of ImGui calls, from here to here
    dev_lua();
    dev_frame();
    let original: PlayerUpdate = std::mem::transmute(PLAYER_UPDATE.get().unwrap().trampoline());
    original(player, dt, input)
}

/// F7 toggles the free camera. F8 in free camera teleports the avatar to it and switches back to the avatar;
/// without free camera it blinks the avatar 20 m along the view.
unsafe fn dev_keys(player: *const u8) {
    let (free_cam, teleport) = (pressed(VK_F7, 0), pressed(VK_F8, 1));
    if !(free_cam || teleport) {
        return;
    }
    let exe = EXE.load(std::sync::atomic::Ordering::Relaxed);
    if !is_a(player, exe.add(PLAYER_TYPE_RVA)) {
        return log("dev: key pressed, but the update was not for an SFHumanPlayer");
    }
    let avatar = read_ptr(read_ptr(player.add(PLAYER_AVATAR)));
    let toggle: unsafe extern "C" fn(*const u8) = std::mem::transmute(exe.add(TOGGLE_FREE_CAMERA_RVA));
    if free_cam {
        toggle(player);
        log(&format!("dev: free camera {}", *player.add(PLAYER_FREE_CAMERA) != 0));
    }
    if teleport {
        if avatar.is_null() {
            return log("dev: no avatar to teleport");
        }
        let in_free_cam = *player.add(PLAYER_FREE_CAMERA) != 0;
        let target = if in_free_cam {
            let Some(at) = free_camera_position(player) else {
                return log("dev: no finite free camera position, teleport skipped");
            };
            Vec4([at[0], at[1], at[2], 0.0])
        } else {
            let Some(view) = camera_world(exe, player) else {
                return log("dev: no finite camera transform, teleport skipped");
            };
            let w = &view.0;
            log(&format!("dev: camera at {:?}, forward {:?}", &w[12..15], &w[8..11]));
            Vec4([w[12] + w[8] * BLINK_DISTANCE, w[13] + w[9] * BLINK_DISTANCE, w[14] + w[10] * BLINK_DISTANCE, 0.0])
        };
        let to_quat: unsafe extern "C" fn(*mut Vec4, f32, f32, f32) -> *mut Vec4 = std::mem::transmute(exe.add(EULER_TO_QUAT_RVA));
        let mut rotation = Vec4([0.0; 4]);
        to_quat(&mut rotation, 0.0, 0.0, 0.0);
        let before = position(avatar);
        let teleport: unsafe extern "C" fn(*const u8, *const Vec4, *const Vec4) = std::mem::transmute(vfunc(avatar, ENTITY_TELEPORT_VSLOT));
        teleport(avatar, &target, &rotation);
        log(&format!("dev: teleport {before:?} -> {:?}, now {:?}", &target.0[..3], position(avatar)));
        if in_free_cam {
            toggle(player); // back to the avatar, which is now where the free camera was
        }
    }
}

unsafe extern "C" fn hook_set_map_marker(l: *mut u8) -> i32 {
    let (x, z) = (imgui::number(l, 2).unwrap_or(0.0), imgui::number(l, 3).unwrap_or(0.0));
    let marker = (x != 0.0 || z != 0.0).then_some((x, z));
    if let Ok(mut m) = MAP_MARKER.lock() {
        if *m != marker {
            log(&format!("dev: map marker {marker:?}"));
        }
        *m = marker;
    }
    let original: LuaNative = std::mem::transmute(SET_MAP_MARKER.get().unwrap().trampoline());
    original(l)
}

/// Only remembers which lua_State the engine loads its scripts into (findings/0030: [script manager+0x20]).
unsafe extern "C" fn hook_load_chunk(l: *mut u8, name: *const c_char, data: *const u8, size: usize, env: i32) -> i32 {
    if LUA.swap(l, std::sync::atomic::Ordering::Relaxed) != l {
        log(&format!("dev: script VM lua_State {l:p}"));
    }
    let original: LoadChunk = std::mem::transmute(LOAD_CHUNK.get().unwrap().trampoline());
    original(l, name, data, size, env)
}

/// When dev.luac (next to this DLL) changes, run it once on a new Luau thread, the way the engine's loader runs a
/// script (0x4f2730: newthread, lua_ref, pop). Errors and a returned string go to sf-bootstrap.log.
// ponytail: the lua_State is whatever the loader saw last; if a VM reset ever frees it before the next load, this
// would touch a dead state. Read it from the script manager instead if that shows up.
unsafe fn dev_lua() {
    static STAMP: Mutex<Option<std::time::SystemTime>> = Mutex::new(None);
    let l = LUA.load(std::sync::atomic::Ordering::Relaxed);
    let path = beside_dll("dev.luac");
    let Ok(modified) = std::fs::metadata(&path).and_then(|m| m.modified()) else { return };
    let Ok(mut stamp) = STAMP.lock() else { return };
    if l.is_null() || *stamp == Some(modified) {
        return;
    }
    *stamp = Some(modified);
    let Ok(code) = std::fs::read(&path) else { return log(&format!("dev: can't read {}", path.display())) };
    let exe = EXE.load(std::sync::atomic::Ordering::Relaxed);
    let checkstack: unsafe extern "C" fn(*mut u8, i32) -> i32 = std::mem::transmute(exe.add(LUA_CHECKSTACK_RVA));
    let newthread: unsafe extern "C" fn(*mut u8) -> *mut u8 = std::mem::transmute(exe.add(LUA_NEWTHREAD_RVA));
    let lua_ref: unsafe extern "C" fn(*mut u8, i32) -> i32 = std::mem::transmute(exe.add(LUA_REF_RVA));
    let settop: unsafe extern "C" fn(*mut u8, i32) = std::mem::transmute(exe.add(LUA_SETTOP_RVA));
    let resume: unsafe extern "C" fn(*mut u8, *mut u8, i32) -> i32 = std::mem::transmute(exe.add(LUA_RESUME_RVA));
    let load: LoadChunk = std::mem::transmute(LOAD_CHUNK.get().unwrap().trampoline());
    if checkstack(l, 1) == 0 {
        return log("dev: no stack room on the script VM, dev.luac skipped");
    }
    let thread = newthread(l);
    // ponytail: one registry ref per run, never released (a few bytes per reload); lua_unref if that ever matters.
    lua_ref(l, -1);
    settop(l, -2);
    let status = load(thread, c"=dev.lua".as_ptr(), code.as_ptr(), code.len(), 0);
    if status != 0 {
        return log(&format!("dev: load failed ({status}): {}", top_text(thread)));
    }
    // The previous panel keeps running unless this chunk returns a new frame function.
    match resume(thread, std::ptr::null_mut(), 0) {
        0 => {
            log(&format!("dev: dev.lua ran, returned {}", top_text(thread)));
            // `return frame, (command)`: keep the frame function as the thread's only value (the thread is ref'd).
            let base = read_ptr(thread.add(LUA_BASE));
            if base < read_ptr(thread.add(LUA_TOP)) && base.add(TVALUE_TAG).cast::<i32>().read_unaligned() == TAG_FUNCTION {
                settop(thread, 1);
                DEV_FRAME.store(thread, std::sync::atomic::Ordering::Relaxed);
            }
        }
        1 => log("dev: dev.lua yielded (Sleep?); it is not resumed again"),
        status => log(&format!("dev: dev.lua failed ({status}): {}", top_text(thread))),
    }
}

/// While the overlay is shown, call the frame function dev.luac returned (the SF dev panel, dev/dev.lua). The thread
/// is reused: a finished Luau thread with an empty call stack can be resumed with a fresh function.
unsafe fn dev_frame() {
    use std::sync::atomic::Ordering::Relaxed;
    let thread = DEV_FRAME.load(Relaxed);
    let teleport = MARKER_TELEPORT.swap(false, Relaxed);
    if thread.is_null() || !(imgui::VISIBLE.load(Relaxed) || teleport || frame_busy()) {
        if teleport {
            log("dev: F10 needs the SF dev panel: run `python tools/devlua.py` once");
        }
        return;
    }
    let exe = EXE.load(Relaxed);
    let pushvalue: unsafe extern "C" fn(*mut u8, i32) = std::mem::transmute(exe.add(LUA_PUSHVALUE_RVA));
    let settop: unsafe extern "C" fn(*mut u8, i32) = std::mem::transmute(exe.add(LUA_SETTOP_RVA));
    let resume: unsafe extern "C" fn(*mut u8, *mut u8, i32) -> i32 = std::mem::transmute(exe.add(LUA_RESUME_RVA));
    if *thread.add(LUA_STATUS) != 0 {
        return DEV_FRAME.store(std::ptr::null_mut(), Relaxed);
    }
    let reset_interrupts: unsafe extern "C" fn(*mut u8) = std::mem::transmute(exe.add(LUA_RESET_INTERRUPTS_RVA));
    pushvalue(thread, 1);
    // frame(teleport_to_marker, marker_x, marker_z): dev.lua has no other way to read the marker.
    imgui::push_bool(thread, teleport);
    let mut nargs = 1;
    if let Some((x, z)) = MAP_MARKER.lock().ok().and_then(|m| *m) {
        imgui::push_number(thread, x);
        imgui::push_number(thread, z);
        nargs = 3;
    }
    reset_interrupts(thread); // as the engine's scheduler does before each resume
    match resume(thread, std::ptr::null_mut(), nargs) {
        0 => {
            // A true return: dev.lua is still busy (snapping a marker teleport to the ground), call it again next frame.
            let base = read_ptr(thread.add(LUA_BASE));
            let busy = base.add(16) < read_ptr(thread.add(LUA_TOP))
                && base.add(16 + TVALUE_TAG).cast::<i32>().read_unaligned() == 1
                && base.add(16).cast::<i32>().read_unaligned() != 0;
            FRAME_BUSY.store(busy, Relaxed);
            settop(thread, 1)
        }
        status => {
            // ponytail: one error stops the panel until the next devlua.py build; dev.lua pcalls what can fail.
            log(&format!("dev: frame function stopped ({status}): {}", top_text(thread)));
            DEV_FRAME.store(std::ptr::null_mut(), Relaxed);
        }
    }
}

static FRAME_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn frame_busy() -> bool {
    FRAME_BUSY.load(std::sync::atomic::Ordering::Relaxed)
}

/// The value on top of a thread's stack, as text when it's a string.
unsafe fn top_text(thread: *mut u8) -> String {
    let (top, base) = (read_ptr(thread.add(LUA_TOP)), read_ptr(thread.add(LUA_BASE)));
    if top <= base {
        return "nothing".into();
    }
    let value = top.wrapping_sub(16);
    let tag = value.add(TVALUE_TAG).cast::<i32>().read_unaligned();
    let string = read_ptr(value);
    if tag != TAG_STRING || !readable(string, TSTRING_DATA) {
        return format!("a value with Luau tag {tag}");
    }
    let len = (string.add(TSTRING_LEN).cast::<u32>().read_unaligned() as usize).min(4000);
    if !readable(string, TSTRING_DATA + len) {
        return "an unreadable string".into();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(string.add(TSTRING_DATA), len)).into_owned()
}

/// The base player update (0x137d720) flies [[player+0x30]] while free camera is on: it writes the rotation (+0x90),
/// velocity (+0x7d0) and angles (+0x7e0) there, so its entity position (+0x70) is the free camera position, in the
/// same space as Teleport. (Box runs 20:03-20:16 looked in the player, the avatar and [[player+0xd0]] instead.)
unsafe fn free_camera_position(player: *const u8) -> Option<[f32; 3]> {
    let entity = handle_target(player.add(PLAYER_FREE_CAMERA_ENTITY));
    if !readable(entity, ENTITY_POSITION + 12) {
        return None;
    }
    let at = position(entity);
    let vtable = (read_ptr(entity) as usize).wrapping_sub(EXE.load(std::sync::atomic::Ordering::Relaxed) as usize);
    log(&format!("dev: free camera entity vtable rva {vtable:#x} at {at:?}"));
    at.iter().all(|v| v.is_finite()).then_some(at)
}

/// Engine RTTI: [object+8] is its type, each type links its parent at +0x18.
unsafe fn is_a(object: *const u8, wanted: *const u8) -> bool {
    let mut ty = read_ptr(object.add(8));
    while !ty.is_null() {
        if ty == wanted {
            return true;
        }
        ty = read_ptr(ty.add(0x18));
    }
    false
}

/// Same as Luau GetViewPosition on the player's camera [[player+0xd0]]: the inverse of its view matrix (+0x30) is the
/// camera's world transform; row 3 is the position (box run 20:10 matched the avatar), row 2 the view direction.
/// Frozen while free camera is on. (Box runs 19:54-20:06: the avatar, the player and camera+0x70 were wrong guesses.)
unsafe fn camera_world(exe: *const u8, player: *const u8) -> Option<Mat4> {
    let matrix = handle_target(player.add(PLAYER_CAMERA)).wrapping_add(CAMERA_VIEW_MATRIX).cast::<Mat4>();
    // The inverse reads with aligned SSE loads; refuse anything that would fault.
    if matrix as usize % 16 != 0 || !readable(matrix.cast(), size_of::<Mat4>()) {
        return None;
    }
    let invert: unsafe extern "C" fn(*const Mat4, *mut Mat4) -> *mut Mat4 = std::mem::transmute(exe.add(INVERT_RVA));
    let mut world = Mat4([0.0; 16]);
    invert(matrix, &mut world);
    // A NaN teleport wrecks the avatar (box run 19:59).
    world.0.iter().all(|v| v.is_finite()).then_some(world)
}

/// Engine handles: the field points at a refcounted node whose first word is the object.
unsafe fn handle_target(field: *const u8) -> *const u8 {
    let handle = read_ptr(field);
    if readable(handle, 8) { read_ptr(handle) } else { std::ptr::null() }
}

unsafe fn readable(at: *const u8, len: usize) -> bool {
    #[repr(C)]
    #[derive(Default)]
    struct MemoryBasicInformation {
        base: usize,
        allocation_base: usize,
        allocation_protect: u32,
        partition: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }
    const MEM_COMMIT: u32 = 0x1000;
    const READABLE: u32 = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80; // READONLY, READWRITE, WRITECOPY, EXECUTE_*
    let mut info = MemoryBasicInformation::default();
    if at.is_null() || VirtualQuery(at.cast(), (&raw mut info).cast(), size_of::<MemoryBasicInformation>()) == 0 {
        return false;
    }
    info.state == MEM_COMMIT && info.protect & READABLE != 0 && at as usize + len <= info.base + info.region_size
}

unsafe fn position(entity: *const u8) -> [f32; 3] {
    entity.add(ENTITY_POSITION).cast::<[f32; 3]>().read_unaligned()
}

unsafe fn vfunc(object: *const u8, slot: usize) -> *const c_void {
    read_ptr(read_ptr(object).add(slot)).cast()
}

unsafe fn read_ptr(at: *const u8) -> *const u8 {
    at.cast::<*const u8>().read_unaligned()
}

/// Key went down since the last poll, only while the game window has focus.
unsafe fn pressed(vk: i32, bit: u8) -> bool {
    static DOWN: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
    let mut pid = 0;
    GetWindowThreadProcessId(GetForegroundWindow(), &mut pid);
    let state = GetAsyncKeyState(vk) as u16;
    let down = state & 0x8000 != 0;
    let was_down = DOWN.load(std::sync::atomic::Ordering::Relaxed) & (1 << bit) != 0;
    if down {
        DOWN.fetch_or(1 << bit, std::sync::atomic::Ordering::Relaxed);
    } else {
        DOWN.fetch_and(!(1 << bit), std::sync::atomic::Ordering::Relaxed);
    }
    // Bit 0: tapped between two polls.
    let edge = state & 1 != 0 || (down && !was_down);
    if edge && pid != GetCurrentProcessId() {
        log(&format!("dev: key {vk:#x} ignored, foreground window belongs to pid {pid}"));
        return false;
    }
    edge
}

fn log(line: &str) {
    static FILE: OnceLock<Option<Mutex<std::fs::File>>> = OnceLock::new();
    let file = FILE.get_or_init(|| {
        let path = std::path::Path::new(&std::env::var_os("LOCALAPPDATA")?).join("Soulframe\\sf-bootstrap.log");
        std::fs::OpenOptions::new().create(true).append(true).open(path).ok().map(Mutex::new)
    });
    if let Some(Ok(mut f)) = file.as_ref().map(Mutex::lock) {
        let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
        let _ = writeln!(f, "{:.3} {line}", unix.as_secs_f64());
    }
}

const fn wide<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    let mut out = [0u16; N];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_only_soulframe_hosts() {
        for host in ["api.soulframe.com", "ORIGIN.SoulFrame.com", "content.soulframe.com.", "soulframe.com"] {
            assert!(redirected(host), "{host}");
        }
        for host in ["notsoulframe.com", "soulframe.com.evil.net", "discord.com", "", "127.0.0.1"] {
            assert!(!redirected(host), "{host}");
        }
    }

    /// Map the pinned exe like the loader would, then run the same build check the DLL runs in the box.
    #[test]
    fn pinned_exe_passes_build_check() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../soulframe-builds/P16H6/pristine/Soulframe.x64.exe");
        let Ok(image) = map_pinned(path) else { return eprintln!("skipped: no {path}") };
        assert_eq!(unsafe { check_build(image.as_ptr()) }, Ok(()));
    }

    /// The exe's sections at their RVAs, as the loader maps them.
    pub(crate) fn map_pinned(path: &str) -> std::io::Result<Vec<u8>> {
        let file = std::fs::read(path)?;
        let u32_at = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
        let nt = u32_at(0x3c) as usize;
        let mut image = vec![0u8; PIN_SIZE_OF_IMAGE as usize];
        image[..0x1000].copy_from_slice(&file[..0x1000]);
        let sections = nt + 0x18 + u16::from_le_bytes([file[nt + 0x14], file[nt + 0x15]]) as usize;
        for s in 0..u16::from_le_bytes([file[nt + 6], file[nt + 7]]) as usize {
            let at = sections + s * 40;
            let (va, raw_size, raw) = (u32_at(at + 12) as usize, u32_at(at + 16) as usize, u32_at(at + 20) as usize);
            image[va..va + raw_size].copy_from_slice(&file[raw..raw + raw_size]);
        }
        Ok(image)
    }

    #[test]
    fn wide_is_nul_terminated() {
        let w = wide::<11>("ws2_32.dll");
        assert_eq!((w[10], String::from_utf16_lossy(&w[..10])), (0, "ws2_32.dll".to_string()));
    }

    #[test]
    fn server_address_is_first_plain_line() {
        assert_eq!(server_address("# my friend\n\n 100.64.1.2 \nignored"), Some("100.64.1.2".into()));
        assert_eq!(server_address("my-pc.tailnet.ts.net"), Some("my-pc.tailnet.ts.net".into()));
        for bad in ["", "# only a comment", "api.soulframe.com", "http://1.2.3.4/", "a b"] {
            assert_eq!(server_address(bad), None, "{bad}");
        }
    }
}
