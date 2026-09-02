use std::collections::HashMap;

use shelllist_daemon_core::IdSequence;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

struct OwnedTask {
    owner: Option<String>,
    task: JoinHandle<()>,
}

pub struct OwnedTaskRegistry {
    ids: IdSequence,
    tasks: Mutex<HashMap<String, OwnedTask>>,
}

impl OwnedTaskRegistry {
    #[must_use]
    pub fn new(first_id: u64) -> Self {
        Self {
            ids: IdSequence::new(first_id),
            tasks: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn next_id(&self, prefix: &str) -> String {
        self.ids.next(prefix)
    }

    pub async fn insert(&self, id: String, owner: Option<String>, task: JoinHandle<()>) {
        if let Some(previous) = self
            .tasks
            .lock()
            .await
            .insert(id, OwnedTask { owner, task })
        {
            previous.task.abort();
        }
    }

    pub async fn remove(&self, id: &str) -> bool {
        self.tasks.lock().await.remove(id).is_some()
    }

    pub async fn cancel_owned(&self, id: &str, owner: Option<&str>) -> bool {
        let mut tasks = self.tasks.lock().await;
        let owned = tasks
            .get(id)
            .is_some_and(|task| task.owner.as_deref() == owner);
        if !owned {
            return false;
        }
        if let Some(task) = tasks.remove(id) {
            task.task.abort();
            true
        } else {
            false
        }
    }

    pub async fn cancel_owner(&self, owner: &str) -> usize {
        let mut tasks = self.tasks.lock().await;
        let ids = tasks
            .iter()
            .filter(|(_, task)| task.owner.as_deref() == Some(owner))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in &ids {
            if let Some(task) = tasks.remove(id) {
                task.task.abort();
            }
        }
        ids.len()
    }

    pub async fn cancel_all(&self) {
        let mut tasks = self.tasks.lock().await;
        tasks.drain().for_each(|(_, task)| task.task.abort());
    }
}

impl Default for OwnedTaskRegistry {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedTaskRegistry;

    #[tokio::test]
    async fn cancellation_is_owner_scoped() {
        let registry = OwnedTaskRegistry::default();
        let id = registry.next_id("subscription");
        registry
            .insert(
                id.clone(),
                Some(":1.7".into()),
                tokio::spawn(std::future::pending()),
            )
            .await;
        assert!(!registry.cancel_owned(&id, Some(":1.8")).await);
        assert!(registry.cancel_owned(&id, Some(":1.7")).await);
    }
}
