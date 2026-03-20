use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use dashmap::DashMap;

pub struct SnapshotCache {
    entries: DashMap<String, CachedSnapshot>,
    recency: Mutex<std::collections::VecDeque<String>>,  // front=oldest, back=newest
    max_size_bytes: usize,
    current_size_bytes: AtomicUsize,
}

pub struct CachedSnapshot {
    pub raw_items: Vec<serde_json::Value>,
    pub created_at: Instant,
    pub tool_name: String,
    size_bytes: usize,
}

impl SnapshotCache {
    pub fn new(max_size_bytes: usize, _ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            recency: Mutex::new(std::collections::VecDeque::new()),
            max_size_bytes,
            current_size_bytes: AtomicUsize::new(0),
        }
    }

    /// Insert a snapshot. Returns the generated snapshot_id.
    pub fn insert(&self, prefix: &str, tool_name: String, raw_items: Vec<serde_json::Value>) -> String {
        let serialized = serde_json::to_string(&raw_items).unwrap_or_default();
        let size_bytes = serialized.len();

        let id = format!("{}_{:08x}", prefix, rand_u32());

        let snapshot = CachedSnapshot {
            raw_items,
            created_at: Instant::now(),
            tool_name,
            size_bytes,
        };

        self.entries.insert(id.clone(), snapshot);
        self.current_size_bytes.fetch_add(size_bytes, Ordering::Relaxed);

        {
            let mut recency = self.recency.lock().unwrap();
            recency.push_back(id.clone());
        }

        self.evict_if_over_limit();
        id
    }

    /// Get a snapshot. Returns None if not found or expired.
    pub fn get(&self, id: &str, ttl: Duration) -> Option<dashmap::mapref::one::Ref<String, CachedSnapshot>> {
        let entry = self.entries.get(id)?;
        if entry.created_at.elapsed() > ttl {
            drop(entry);
            if let Some((_, snapshot)) = self.entries.remove(id) {
                self.current_size_bytes.fetch_sub(snapshot.size_bytes, Ordering::Relaxed);
            }
            return None;
        }
        Some(entry)
    }

    fn evict_if_over_limit(&self) {
        while self.current_size_bytes.load(Ordering::Relaxed) > self.max_size_bytes {
            let oldest = {
                let mut recency = self.recency.lock().unwrap();
                if recency.is_empty() { break; }
                recency.pop_front().unwrap()
            };
            if let Some((_, snapshot)) = self.entries.remove(&oldest) {
                self.current_size_bytes.fetch_sub(snapshot.size_bytes, Ordering::Relaxed);
            }
        }
    }
}

fn rand_u32() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = Cell::new({
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64
                | 0x1234_5678_0000_0001
        });
    }
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x as u32
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_items(n: usize) -> Vec<serde_json::Value> {
        (0..n).map(|i| json!({"index": i})).collect()
    }

    #[test]
    fn insert_and_get_returns_items() {
        let cache = SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600));
        let items = make_items(3);
        let id = cache.insert("ph", "get_proxy_http_history".into(), items.clone());
        assert!(id.starts_with("ph_"));
        let snapshot = cache.get(&id, Duration::from_secs(600)).unwrap();
        assert_eq!(snapshot.raw_items.len(), 3);
        assert_eq!(snapshot.tool_name, "get_proxy_http_history");
    }

    #[test]
    fn get_expired_returns_none() {
        let cache = SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600));
        let id = cache.insert("ph", "get_proxy_http_history".into(), make_items(1));
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.get(&id, Duration::from_nanos(1)).is_none());
    }

    #[test]
    fn get_unknown_id_returns_none() {
        let cache = SnapshotCache::new(50 * 1024 * 1024, Duration::from_secs(600));
        assert!(cache.get("ph_nope", Duration::from_secs(600)).is_none());
    }

    #[test]
    fn lru_eviction_removes_oldest_when_over_size_limit() {
        // Tiny limit — each item is ~14 bytes serialized ([{"index":0}])
        // limit must be >= 14 (first insert fits) but < 28 (two don't fit)
        let cache = SnapshotCache::new(20, Duration::from_secs(600));
        let id1 = cache.insert("ph", "tool".into(), make_items(1));
        let id2 = cache.insert("ph", "tool".into(), make_items(1));
        // id1 should be evicted since inserting id2 exceeds the 50-byte limit
        assert!(cache.get(&id1, Duration::from_secs(600)).is_none());
        assert!(cache.get(&id2, Duration::from_secs(600)).is_some());
    }
}
