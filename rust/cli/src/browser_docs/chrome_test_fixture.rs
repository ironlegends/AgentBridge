//! Test-only browser selection. Production CLI builds do not contain this module.
use super::{native, refused};
use std::cell::RefCell;
use std::io;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

struct Selection {
    root: native::DirectoryPin,
    executable: PathBuf,
}

thread_local! {
    static SELECTED: RefCell<Option<Selection>> = const { RefCell::new(None) };
}

pub(super) fn selected() -> io::Result<Option<PathBuf>> {
    SELECTED.with(|selection| {
        let selected = selection.borrow();
        let Some(selected) = selected.as_ref() else { return Ok(None); };
        selected.root.require_private()?;
        Ok(Some(selected.executable.clone()))
    })
}

pub(super) struct Guard {
    _same_thread: PhantomData<Rc<()>>,
}

impl Guard {
    pub(super) fn from_env() -> io::Result<Option<Self>> {
        match (
            std::env::var_os("AGENT_BRIDGE_TEST_CHROME_FIXTURE_ROOT"),
            std::env::var_os("AGENT_BRIDGE_TEST_PRIVATE_CHROME"),
        ) {
            (None, None) => Ok(None),
            (Some(root), Some(executable)) => {
                if let Err(issue) = super::installed_system_chrome() {
                    eprintln!("native Chrome fixture does not qualify the system installation: category={:?}, os_code={:?}",
                        issue.kind(), issue.raw_os_error());
                }
                Self::enter(Path::new(&root), Path::new(&executable)).map(Some)
            }
            _ => Err(refused()),
        }
    }

    fn enter(root: &Path, executable: &Path) -> io::Result<Self> {
        let relative = executable.strip_prefix(root).map_err(|_| refused())?;
        if relative.as_os_str().is_empty()
            || relative.components().any(|part| !matches!(part, Component::Normal(_)))
        { return Err(refused()); }
        let root = native::DirectoryPin::open(root)?;
        root.require_private()?;
        native::pin_browser(executable)?;
        SELECTED.with(|selection| {
            let mut selected = selection.borrow_mut();
            if selected.is_some() { return Err(refused()); }
            *selected = Some(Selection { root, executable: executable.to_owned() });
            Ok(Self { _same_thread: PhantomData })
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        SELECTED.with(|selection| *selection.borrow_mut() = None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }
    fn scratch() -> (Scratch, PathBuf) {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = Scratch(base.join(format!("agent-bridge-browser-guard-{}", super::super::random_id().unwrap())));
        fs::DirBuilder::new().mode(0o700).create(&root.0).unwrap();
        let executable = root.0.join("fixture");
        fs::write(&executable, b"test-only selection; never executed").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        (root, executable)
    }
    fn outcome(result: io::Result<PathBuf>) -> Result<PathBuf, (io::ErrorKind, Option<i32>)> {
        result.map_err(|issue| (issue.kind(), issue.raw_os_error()))
    }

    #[test]
    fn fixture_selection_is_thread_local_scoped_and_does_not_change_system_qualification() {
        let (root, executable) = scratch();
        let system = outcome(super::super::installed_system_chrome());
        {
            let _guard = Guard::enter(&root.0, &executable).unwrap();
            assert_eq!(super::super::installed_chrome().unwrap(), executable);
            assert_eq!(outcome(super::super::installed_system_chrome()), system);
            assert!(std::thread::spawn(|| selected().unwrap()).join().unwrap().is_none());
        }
        assert!(selected().unwrap().is_none());
        assert_eq!(outcome(super::super::installed_chrome()), system);
    }

    #[test]
    fn invalid_fixture_is_refused_without_installing_any_override() {
        let (root, executable) = scratch();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Guard::enter(&root.0, &executable).is_err());
        assert!(selected().unwrap().is_none());
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(Guard::enter(&root.0, &std::env::current_exe().unwrap()).is_err());
        assert!(selected().unwrap().is_none());
    }
}
