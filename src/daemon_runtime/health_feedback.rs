//! Per-consumer health feedback policy, before fan-out. No client wall clock,
//! reason table or second failure classifier is required in the frontend.
use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(super) struct HealthFeedback {
    last: HashMap<String, (String, Instant)>,
}
impl HealthFeedback {
    pub(super) fn drop_owner(&mut self, owner: &str) {
        self.last.remove(owner);
    }
    pub(super) fn project(
        &mut self,
        owner: &str,
        data: &Value,
        connecting: bool,
        now: Instant,
    ) -> Value {
        let mut data = data.clone();
        let health = &mut data["health"];
        if health["notification_recommended"] != true {
            return data;
        }
        let identity = [
            "device_path",
            "active_connection_path",
            "profile_path",
            "uuid",
            "id",
            "device_iface",
            "connection_type",
        ]
        .iter()
        .find_map(|key| health[*key].as_str().filter(|v| !v.is_empty()))
        .unwrap_or("network");
        let key = format!(
            "{identity}|{}|{}",
            health["state_name"].as_str().unwrap_or("unknown"),
            health["reason"]["name"].as_str().unwrap_or("unknown")
        );
        let duplicate = self.last.get(owner).is_some_and(|(old, at)| {
            *old == key && now.saturating_duration_since(*at) < Duration::from_secs(3)
        });
        if connecting || duplicate {
            health["notification_recommended"] = Value::Bool(false);
        } else {
            self.last.insert(owner.into(), (key, now));
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn suppresses_duplicates_and_owned_connects_without_suppressing_other_consumers() {
        let value = json!({"health":{"device_path":"/device/1","state_name":"failed","reason":{"name":"no-secrets"},"notification_recommended":true,"message":"Needs credentials"}});
        let mut policy = HealthFeedback::default();
        let now = Instant::now();
        assert_eq!(
            policy.project("a", &value, true, now)["health"]["notification_recommended"],
            false
        );
        assert_eq!(
            policy.project("a", &value, false, now)["health"]["notification_recommended"],
            true
        );
        assert_eq!(
            policy.project("a", &value, false, now + Duration::from_secs(2))["health"]["notification_recommended"],
            false
        );
        assert_eq!(
            policy.project("b", &value, false, now)["health"]["notification_recommended"],
            true
        );
        assert_eq!(
            policy.project("a", &value, false, now + Duration::from_secs(3))["health"]["notification_recommended"],
            true
        );
        policy.drop_owner("a");
        assert_eq!(
            policy.project("a", &value, false, now + Duration::from_secs(3))["health"]["notification_recommended"],
            true
        );
        assert_eq!(
            value["health"]["notification_recommended"], true,
            "fan-out never mutates shared source events"
        );
    }
}
