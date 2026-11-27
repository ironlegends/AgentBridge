use super::*;
use std::cell::RefCell;
use std::rc::Rc;

thread_local! {
    static AFTER_COPY_BLOCK: RefCell<Option<Box<dyn FnMut(&File)>>> = const { RefCell::new(None) };
}
pub(super) fn after_copy_block(destination: &File) {
    AFTER_COPY_BLOCK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() { hook(destination); }
    });
}

#[test]
fn task5_growing_source_never_writes_beyond_its_reserved_length() {
    let root = std::env::temp_dir().join(format!("bridge-growing-source-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    // macOS can return /var as an alias of /private/var. Use the physical fixture path.
    #[cfg(unix)]
    let root = root.canonicalize().unwrap();
    let source_path = root.join("source.bin");
    std::fs::File::create(&source_path).unwrap().set_len(1024 * 1024).unwrap();
    let directory = open_filesystem_root(&root, false).unwrap();
    let mut source = Source::open(directory.try_clone().unwrap(), "source.bin".into()).unwrap();
    let mut destination = directory.open_with("copy.bin", &private_file_options()).unwrap();
    let high_water = Rc::new(RefCell::new(0u64));
    let observed = Rc::clone(&high_water);
    let mut grew = false;
    AFTER_COPY_BLOCK.with(|slot| *slot.borrow_mut() = Some(Box::new(move |destination| {
        let peak = (*observed.borrow()).max(destination.metadata().unwrap().len());
        *observed.borrow_mut() = peak;
        if !grew {
            grew = true;
            std::fs::OpenOptions::new().write(true).open(&source_path).unwrap().set_len(3 * 1024 * 1024).unwrap();
        }
    })));
    let outcome = source.copy_to(&mut destination);
    AFTER_COPY_BLOCK.with(|slot| { slot.borrow_mut().take(); });
    let written = destination.metadata().unwrap().len();
    drop(destination); drop(source); drop(directory);
    std::fs::remove_dir_all(root).unwrap();
    assert!(outcome.is_err(), "a growing source must not publish successfully");
    assert!(written <= 1_048_576 && *high_water.borrow() <= 1_048_576,
        "copy exceeded its 1MiB reservation before refusing growth: final={written}, peak={}", high_water.borrow());
}
