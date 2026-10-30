//! Shared by sf_bootstrap.dll and sf-launch.exe: never touch a real game install, only a copy.

/// True for the official install locations (standalone `%LOCALAPPDATA%\Soulframe\Downloaded\...`, Steam, Epic).
/// The live game must never run with our DLL: it would talk to our server under the player's real install and
/// write `sf-appdata` into it.
pub fn is_official_install(exe: &str) -> bool {
    let p = exe.replace('/', "\\").to_ascii_lowercase();
    ["\\soulframe\\downloaded\\", "\\steamapps\\", "\\epic games\\"].iter().any(|s| p.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_installs_are_refused() {
        for live in [
            r"C:\Users\user\AppData\Local\Soulframe\Downloaded\Public\Soulframe.x64.exe",
            r"D:\SteamLibrary\steamapps\common\Soulframe\Soulframe.x64.exe",
            "C:/Program Files/Epic Games/Soulframe/Soulframe.x64.exe",
        ] {
            assert!(is_official_install(live), "{live}");
        }
        assert!(!is_official_install(r"C:\Users\user\Documents\avakot\soulframe-builds\P16H6\work\Soulframe.x64.exe"));
        // Inside the Sandboxie box the copy keeps its own path.
        assert!(!is_official_install(r"C:\Sandbox\user\SoulframeP16H6\drive\C\Users\x\soulframe-builds\P16H6\work\Soulframe.x64.exe"));
    }
}
