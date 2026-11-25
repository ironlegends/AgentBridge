//! Terminal-specific executable/cwd and cmd.exe parsing.
//! Kernel handles, Job assignment and pipes live in the shared child owner.
use super::{unified, LaunchSpec};
use std::collections::BTreeMap;
use crate::owned_children::{OwnedChild, quote_argument};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf, Prefix};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn command_line(executable: &Path, specification: &LaunchSpec) -> io::Result<Vec<u16>> {
    let mut line = quote_argument(executable.as_os_str())?;
    if let Some(command) = &specification.cmd_command {
        if !specification.arguments.is_empty() || command.contains('\0') {
            return Err(invalid("cmd shell command cannot be combined with argv"));
        }
        // /S removes this outer pair of quotes. Quotes within command retain
        // their cmd.exe meaning; CRT quoting here would change shell syntax.
        line.extend(" /D /S /C \"".encode_utf16());
        line.extend(command.encode_utf16());
        line.push(34);
    } else {
        for argument in &specification.arguments {
            line.push(32);
            // MSCRT does not require quotes for simple nonempty tokens. Keep
            // those tokens plain, as std::process::Command does, so programs
            // with their own option parser do not see unnecessary quotes.
            // This preserves literal argv; no shell parser/fallback is added.
            if argument.is_empty() || argument.chars().any(|ch| matches!(ch, ' ' | '\t' | '"' | '\0')) {
                line.extend(quote_argument(OsStr::new(argument))?);
            } else {
                line.extend(argument.encode_utf16());
            }
        }
    }
    line.push(0);
    if line.len() > 32_767 {
        return Err(invalid("Windows command line exceeds 32767 UTF-16 units"));
    }
    Ok(line)
}

fn executable_candidate(path: &Path) -> io::Result<Option<PathBuf>> {
    let extension = path.extension().and_then(OsStr::to_str);
    let candidate = match extension {
        None => path.with_extension("exe"),
        Some(ext) if ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("com") => {
            path.to_path_buf()
        }
        _ => return Err(invalid("Direct Windows programs must be .exe or .com; use a shell explicitly for scripts")),
    };
    match candidate.metadata() {
        // These candidates are already absolute (cwd/PATH resolution below).
        // Preserve their selected spelling: canonicalize() injects a verbatim
        // \\?\ prefix that breaks legacy .NET/Windows PowerShell startup.
        // Explicitly supplied verbatim paths remain explicit, without rewriting
        // trailing-dot/space or DOS-device path semantics.
        Ok(metadata) if metadata.is_file() => Ok(Some(candidate)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn resolve_program(specification: &LaunchSpec) -> io::Result<PathBuf> {
    if specification.program.is_empty() || specification.program.contains('\0') {
        return Err(invalid("Executable name must be nonempty and contain no NUL"));
    }
    let program = Path::new(&specification.program);
    if program.is_absolute() {
        return executable_candidate(program)?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Executable does not exist")
        });
    }
    if program.has_root() || program.components().any(|part| matches!(part, Component::Prefix(_))) {
        return Err(invalid("Drive-relative and root-relative executable paths are ambiguous"));
    }
    if program.components().count() > 1 {
        return executable_candidate(&specification.cwd.join(program))?.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Executable does not exist in the working directory")
        });
    }
    if let Some(candidate) = executable_candidate(&specification.cwd.join(program))? {
        return Ok(candidate);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                specification.cwd.join(directory)
            };
            if let Some(candidate) = executable_candidate(&directory.join(program))? {
                return Ok(candidate);
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Executable was not found in cwd or PATH"))
}

fn ordinary_component(raw: &OsStr) -> bool {
    let Some(text) = raw.to_str() else { return false; };
    if text.ends_with('.') || text.ends_with(' ')
        || text.chars().any(|ch| ch < ' ' || matches!(ch, ':' | '"' | '<' | '>' | '|' | '?' | '*'))
    {
        return false;
    }
    let upper = text.to_ascii_uppercase();
    let stem = upper.split('.').next().unwrap_or("");
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") { return false; }
    for prefix in ["COM", "LPT"] {
        if let Some(suffix) = stem.strip_prefix(prefix) {
            if suffix.chars().count() == 1
                && suffix.chars().next().is_some_and(|ch| matches!(ch, '1'..='9' | '¹' | '²' | '³'))
            {
                return false;
            }
        }
    }
    true
}

pub(super) fn launch_directory(selected: &Path, cmd_shell: bool) -> io::Result<PathBuf> {
    if !selected.is_absolute() {
        return Err(invalid("Working directory must resolve to an absolute path"));
    }
    let units: Vec<u16> = selected.as_os_str().encode_wide().collect();
    let ordinary = match selected.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::VerbatimDisk(_) => Some(PathBuf::from(OsString::from_wide(&units[4..]))),
            Prefix::VerbatimUNC(_, _) => {
                let mut normal = vec![92, 92];
                normal.extend_from_slice(&units[8..]);
                Some(PathBuf::from(OsString::from_wide(&normal)))
            },
            _ => None,
        },
        _ => None,
    };
    let mut directory = selected.to_path_buf();
    if let Some(candidate) = ordinary {
        // Do not reinterpret explicit verbatim-only names (trailing dots or
        // spaces, device names, etc). Even a normal-looking spelling is used
        // only after checking that both paths resolve to the same directory.
        let safe = candidate.as_os_str().encode_wide().count() < 260
            && candidate.components().all(|component| match component {
                Component::Normal(name) => ordinary_component(name),
                Component::Prefix(_) | Component::RootDir => true,
                _ => false,
            });
        if safe {
            if let (Ok(original), Ok(normal)) = (selected.canonicalize(), candidate.canonicalize()) {
                if original == normal { directory = candidate; }
            }
        }
    }
    if cmd_shell {
        let dos = matches!(directory.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)));
        if !dos || directory.as_os_str().encode_wide().count() >= 260 {
            return Err(invalid(
                "cmd requires an equivalent ordinary DOS working directory shorter than 260 UTF-16 units; UNC or verbatim-only cwd would silently fall back",
            ));
        }
    }
    Ok(directory)
}


pub(super) struct Process(OwnedChild);
impl Process {
    pub(super) fn spawn(specification: &LaunchSpec) -> io::Result<Self> {
        Self::spawn_with_presentation(specification, None)
    }

    pub(super) fn spawn_unified(specification: &LaunchSpec, presentation: &unified::Presentation) -> io::Result<Self> {
        Self::spawn_with_presentation(specification, Some(presentation))
    }

    fn spawn_with_presentation(specification: &LaunchSpec, presentation: Option<&unified::Presentation>) -> io::Result<Self> {
        let executable = resolve_program(specification)?;
        let cmd_image = executable.file_name().and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case("cmd.exe"));
        let cwd = launch_directory(&specification.cwd,
            specification.cmd_command.is_some() || cmd_image)?;
        let mut command = command_line(&executable, specification)?;
        if presentation.is_some() && cmd_image && command.len() > 8192 {
            return Err(invalid("cmd.exe command line exceeds 8191 UTF-16 units"));
        }
        let Some(presentation) = presentation else {
            return Ok(Self(OwnedChild::spawn_terminal(&executable, &mut command, &cwd)?));
        };
        let mut environment = BTreeMap::new();
        if let Some(temp) = &presentation.temp {
            let temp = launch_directory(temp.path(), false)?.into_os_string();
            environment.insert(OsString::from("TEMP"), Some(temp.clone()));
            environment.insert(OsString::from("TMP"), Some(temp));
        }
        Ok(Self(OwnedChild::spawn_terminal_configured(
            &executable, &mut command, &cwd, &environment, presentation.visible,
        )?))
    }

    pub(super) fn owned_child(&self) -> &OwnedChild { &self.0 }

    pub(super) fn read_stdout(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read_stdout(buf) }
    pub(super) fn read_stderr(&mut self, buf: &mut [u8]) -> io::Result<usize> { self.0.read_stderr(buf) }
    pub(super) fn write_stdin(&mut self, buf: &[u8]) -> io::Result<usize> { self.0.write_stdin(buf) }
    pub(super) fn close_stdin(&mut self) { self.0.close_stdin(); }
    pub(super) fn try_exit(&mut self) -> io::Result<Option<Option<i32>>> {
        self.0.try_exit().map(|exit| exit.map(|exit| exit.code))
    }
    pub(super) fn terminate(&mut self) -> io::Result<()> { self.0.terminate() }
    pub(super) fn finish(&mut self) -> io::Result<Option<Option<i32>>> {
        self.0.finish().map(|exit| exit.map(|exit| exit.code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_argv_preserves_empty_quotes_and_trailing_backslashes() {
        for (raw, expected) in [
            ("", "\"\""),
            ("two words", "\"two words\""),
            ("say \"hello\"", "\"say \\\"hello\\\"\""),
            ("C:\\space dir\\", "\"C:\\space dir\\\\\""),
            ("before\\\"after", "\"before\\\\\\\"after\""),
        ] {
            let quoted = quote_argument(OsStr::new(raw)).unwrap();
            assert_eq!(String::from_utf16(&quoted).unwrap(), expected);
        }
        assert!(quote_argument(OsStr::new("bad\0argument")).is_err());
    }

    #[test]
    fn cmd_tail_retains_its_shell_quotes() {
        let specification = LaunchSpec {
            program: "cmd".into(),
            arguments: Vec::new(),
            cwd: PathBuf::from(r"C:\work"),
            cmd_command: Some(r#""C:\space dir\tool.exe" "argument value""#.into()),
        };
        let line = command_line(Path::new(r"C:\Windows\System32\cmd.exe"), &specification).unwrap();
        assert_eq!(
            String::from_utf16(&line[..line.len() - 1]).unwrap(),
            r#""C:\Windows\System32\cmd.exe" /D /S /C ""C:\space dir\tool.exe" "argument value"""#,
        );
    }

    #[test]
    fn canonical_cwd_uses_only_an_equivalent_ordinary_directory() {
        let selected = std::env::temp_dir().canonicalize().unwrap();
        let directory = launch_directory(&selected, true).unwrap();
        assert!(matches!(directory.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))));
        assert_eq!(directory.canonicalize().unwrap(), selected);
    }

    #[test]
    fn verbatim_only_cwd_is_preserved_and_cmd_refuses_a_different_directory() {
        let root = std::env::temp_dir().join(format!("agent-bridge-cwd-{}", super::super::new_session_id().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let canonical = root.canonicalize().unwrap();
        let normal = canonical.join("special");
        let verbatim = canonical.join("special.");
        std::fs::create_dir(&normal).unwrap();
        std::fs::create_dir(&verbatim).unwrap();
        assert_ne!(normal.canonicalize().unwrap(), verbatim.canonicalize().unwrap());
        assert_eq!(launch_directory(&verbatim, false).unwrap(), verbatim);
        assert!(launch_directory(&verbatim, true).is_err());
        std::fs::remove_dir(verbatim).unwrap();
        std::fs::remove_dir(normal).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn cmd_rejects_unc_cwd_spelling() {
        let selected = Path::new(r"\\not-a-connected-host\not-a-share\project");
        assert!(launch_directory(selected, true).is_err());
        assert_eq!(launch_directory(selected, false).unwrap(), selected);
    }
}