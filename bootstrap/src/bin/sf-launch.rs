//! sf-launch.exe: start a *copy* of the game with sf_bootstrap.dll, no Sandboxie needed (Phase 6, for players).
//! - The game's LOCALAPPDATA/APPDATA point into <game dir>\sf-appdata, so EE.cfg, EE.log and account folders never
//!   touch the live game's %LOCALAPPDATA%\Soulframe (findings/0003).
//! - The game starts suspended. It only runs once the DLL signals that every hook is in (right build, redirect, TLS,
//!   AppData); otherwise it's killed before running a single instruction of its own, so it can't reach DE.
//! - It may not start other programs (a job object allows one process): Tools\Launcher.exe or RemoteCrashSender.exe
//!   would run without the DLL and talk to DE (code review 2026-10-29).
//!
//! Usage: sf-launch.exe [path\to\Soulframe.x64.exe] [extra game args]   (default: the exe next to sf-launch.exe)
//! Server: sf-server.txt next to sf_bootstrap.dll (one line, the host's address; default 127.0.0.1).

#[path = "../live.rs"]
mod live;

use std::ffi::c_void;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const CREATE_SUSPENDED: u32 = 0x4;
// The same flags the official launcher uses (EE.log), as tools\play.ps1 does.
const GAME_ARGS: [&str; 6] =
    ["-windowMode:2", "-shaderCache:1", "-graphicsDriver:dx11", "-gpuPreference:2", "-cluster:public", "-language:en"];
const HOOK_TIMEOUT_MS: u32 = 30_000;

#[link(name = "kernel32")]
extern "system" {
    fn VirtualAllocEx(process: *mut c_void, at: *const c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
    fn WriteProcessMemory(process: *mut c_void, at: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
    fn CreateRemoteThread(
        process: *mut c_void, attrs: *const c_void, stack: usize, start: *const c_void, param: *mut c_void, flags: u32,
        id: *mut u32,
    ) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, ms: u32) -> u32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn CreateEventW(attrs: *const c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
    fn GetModuleHandleW(name: *const u16) -> *const c_void;
    fn GetProcAddress(module: *const c_void, name: *const u8) -> *const c_void;
    fn GetLastError() -> u32;
    fn CreateJobObjectW(attrs: *const c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(job: *mut c_void, class: u32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
}

#[repr(C)]
#[derive(Default)]
struct JobBasicLimits {
    per_process_user_time: i64,
    per_job_user_time: i64,
    flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_processes: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}
#[link(name = "ntdll")]
extern "system" {
    fn NtResumeProcess(process: *mut c_void) -> i32;
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sf-launch: {e}\nPress Enter to close.");
            let _ = std::io::stdin().read_line(&mut String::new()); // a double-clicked console would vanish
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let here = std::env::current_exe().map_err(|e| e.to_string())?.parent().unwrap().to_path_buf();
    let mut args = std::env::args_os().skip(1);
    let exe = std::path::absolute(args.next().map(PathBuf::from).unwrap_or_else(|| here.join("Soulframe.x64.exe")))
        .map_err(|e| e.to_string())?;
    let dll = here.join("sf_bootstrap.dll");
    for f in [&exe, &dll] {
        if !f.is_file() {
            return Err(format!("{} not found", f.display()));
        }
    }
    if live::is_official_install(&exe.to_string_lossy()) {
        return Err(format!("{} is your real game install. Copy the whole game folder somewhere else and run that copy.", exe.display()));
    }
    firewalled(&exe)?;
    let game_dir = exe.parent().unwrap();
    let appdata = game_dir.join("sf-appdata");
    let (local, roaming) = (appdata.join("Local"), appdata.join("Roaming"));
    std::fs::create_dir_all(local.join("Soulframe")).map_err(|e| format!("{}: {e}", appdata.display()))?;
    std::fs::create_dir_all(&roaming).map_err(|e| format!("{}: {e}", appdata.display()))?;

    let mut child = Command::new(&exe)
        .args(GAME_ARGS)
        .args(args)
        .current_dir(game_dir) // the game logs and may resolve paths from its working directory
        .env("LOCALAPPDATA", &local)
        .env("APPDATA", &roaming)
        .creation_flags(CREATE_SUSPENDED)
        .spawn()
        .map_err(|e| format!("starting {}: {e}", exe.display()))?;
    let process = child.as_raw_handle();
    let started = unsafe { start(process, child.id(), &dll) };
    if let Err(e) = started {
        let _ = child.kill();
        return Err(format!("{e}\nThe game was stopped before it ran. Log: {}", local.join("Soulframe\\sf-bootstrap.log").display()));
    }
    println!("started {} (AppData in {})", exe.display(), appdata.display());
    Ok(())
}

/// The copy must have an enabled outbound block rule (tools\isolate-build.ps1 -Path, as admin), the same check as
/// tools\play.ps1. The DLL redirects what it knows about; the firewall stops whatever it doesn't.
fn firewalled(exe: &Path) -> Result<(), String> {
    if on_wine() {
        return offline();
    }
    let quoted = exe.to_string_lossy().replace('\'', "''");
    let script = format!(
        "if (Get-NetFirewallProfile | Where-Object {{ -not $_.Enabled }}) {{ 'profile-off'; exit }}
         $r = Get-NetFirewallApplicationFilter -Program '{quoted}' -ErrorAction SilentlyContinue | Get-NetFirewallRule |
             Where-Object {{ $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }}
         if ($r) {{ 'ok' }} else {{ 'no-rule' }}"
    );
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .map_err(|e| format!("could not check the firewall: {e}"))?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "ok" => Ok(()),
        "profile-off" => Err("a Windows Firewall profile is turned off; turn it on first".into()),
        _ => Err(format!(
            "no firewall rule blocks {}.\nRun once, as admin: tools\\isolate-build.ps1 -Path \"{}\" -Server <host address>",
            exe.display(),
            exe.parent().unwrap().display()
        )),
    }
}

/// Wine's ntdll exports wine_get_version; Windows' doesn't.
fn on_wine() -> bool {
    let ntdll: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    unsafe { !GetProcAddress(GetModuleHandleW(ntdll.as_ptr()), c"wine_get_version".as_ptr().cast()).is_null() }
}

/// Linux has no Windows Firewall to ask, so test the real thing: the nftables rule from release/join/setup.sh
/// rejects everything but the host and loopback for this user. Any public address answering means it isn't loaded.
fn offline() -> Result<(), String> {
    use std::net::{SocketAddr, TcpStream};
    for addr in ["1.1.1.1:443", "9.9.9.9:443", "8.8.8.8:53"] {
        if TcpStream::connect_timeout(&addr.parse::<SocketAddr>().unwrap(), std::time::Duration::from_secs(3)).is_ok() {
            return Err(format!(
                "this copy can reach the internet ({addr}), so the firewall rule is missing.\nRun play.sh (not wine directly), or setup.sh again."
            ));
        }
    }
    Ok(())
}

/// Inject the DLL into the suspended game, wait for its "all hooked" event, then let the game run.
unsafe fn start(process: *mut c_void, pid: u32, dll: &Path) -> Result<(), String> {
    let name: Vec<u16> = format!("Local\\sf-bootstrap-ready-{pid}\0").encode_utf16().collect();
    let ready = CreateEventW(std::ptr::null(), 1, 0, name.as_ptr());
    const ERROR_ALREADY_EXISTS: u32 = 183;
    if ready.is_null() || GetLastError() == ERROR_ALREADY_EXISTS {
        // An existing event could already be set, which would start the game without its hooks.
        return Err("could not create a fresh ready event".into());
    }
    let result = one_process_only(process).and_then(|()| inject(process, dll)).and_then(|()| match WaitForSingleObject(ready, HOOK_TIMEOUT_MS) {
        0 => Ok(()),
        _ => Err("sf_bootstrap.dll did not finish hooking (unsupported game build?)".into()),
    });
    CloseHandle(ready);
    result?;
    match NtResumeProcess(process) {
        0 => Ok(()),
        status => Err(format!("resuming the game failed ({status:#x})")),
    }
}

unsafe fn inject(process: *mut c_void, dll: &Path) -> Result<(), String> {
    const MEM_COMMIT_RESERVE: u32 = 0x3000;
    const PAGE_READWRITE: u32 = 4;
    let path: Vec<u16> = dll.as_os_str().encode_wide().chain([0]).collect();
    let size = path.len() * 2;
    let remote = VirtualAllocEx(process, std::ptr::null(), size, MEM_COMMIT_RESERVE, PAGE_READWRITE);
    if remote.is_null() || WriteProcessMemory(process, remote, path.as_ptr().cast(), size, std::ptr::null_mut()) == 0 {
        return Err("could not write the DLL path into the game".into());
    }
    // kernel32 sits at the same address in every process of a boot, so our LoadLibraryW is the game's too.
    let kernel32: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    let load_library = GetProcAddress(GetModuleHandleW(kernel32.as_ptr()), c"LoadLibraryW".as_ptr().cast());
    let thread = CreateRemoteThread(process, std::ptr::null(), 0, load_library, remote, 0, std::ptr::null_mut());
    if thread.is_null() {
        return Err("could not start the loader thread in the game".into());
    }
    // The exit code is only the low 32 bits of the module handle, so it can't prove the load; the ready event does.
    let waited = WaitForSingleObject(thread, HOOK_TIMEOUT_MS);
    CloseHandle(thread);
    match waited {
        0 => Ok(()),
        _ => Err("loading sf_bootstrap.dll timed out".into()),
    }
}

/// Put the game in a job that allows exactly one process, so anything it tries to start fails.
/// The job lives as long as the game does, even after sf-launch exits.
unsafe fn one_process_only(process: *mut c_void) -> Result<(), String> {
    const JOB_OBJECT_BASIC_LIMIT_INFORMATION: u32 = 2;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x8;
    let limits = JobBasicLimits { flags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS, active_processes: 1, ..Default::default() };
    let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
    let ok = !job.is_null()
        && SetInformationJobObject(job, JOB_OBJECT_BASIC_LIMIT_INFORMATION, (&raw const limits).cast(), size_of::<JobBasicLimits>() as u32) != 0
        && AssignProcessToJobObject(job, process) != 0;
    if ok { Ok(()) } else { Err(format!("could not limit the game to one process (error {})", GetLastError())) }
}
