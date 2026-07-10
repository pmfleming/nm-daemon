use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static CANCELLABLES: OnceLock<Mutex<HashMap<String, Arc<AtomicBool>>>> = OnceLock::new();

type CancelFlag = Arc<AtomicBool>;

pub(crate) fn register(id: &str) -> CancelFlag {
    let flag = Arc::new(AtomicBool::new(false));
    cancellables()
        .lock()
        .expect("daemon cancellation map poisoned")
        .insert(id.to_string(), Arc::clone(&flag));
    flag
}

pub(crate) fn cancel(id: &str) -> bool {
    cancellables()
        .lock()
        .expect("daemon cancellation map poisoned")
        .get(id)
        .is_some_and(|flag| {
            flag.store(true, Ordering::Relaxed);
            true
        })
}

pub(crate) fn remove(id: &str) {
    cancellables()
        .lock()
        .expect("daemon cancellation map poisoned")
        .remove(id);
}

pub(crate) fn is_cancelled(flag: &AtomicBool) -> bool {
    flag.load(Ordering::Relaxed)
}

fn cancellables() -> &'static Mutex<HashMap<String, CancelFlag>> {
    CANCELLABLES.get_or_init(|| Mutex::new(HashMap::new()))
}
