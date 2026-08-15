//! Rate limiting for key operations — the last leg of T9.
//!
//! The gate answers "may this request happen?". This answers "may this many
//! of them?". Without it a compromised gateway holds a valid credential and
//! can drain a database one legitimate-looking DecryptField at a time; the
//! purpose check would pass every single call.
//!
//! Token bucket per (tenant, operation): a burst is fine, a sustained flood
//! is not.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Injected so tests can advance time without sleeping.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<(String, &'static str), Bucket>>,
    /// Per-operation ceiling across ALL tenants. This is the limit that
    /// actually binds a compromised gateway: T9 assumes the caller is
    /// hostile, and a hostile caller invents tenant ids, so a per-tenant
    /// bucket alone is fairness, not a control.
    global: Mutex<HashMap<&'static str, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
    global_capacity: f64,
    global_refill_per_sec: f64,
    /// Upper bound on tracked keys. Without it, a caller inventing tenant ids
    /// would turn the limiter itself into a memory exhaustion vector.
    max_buckets: usize,
    clock: Box<dyn Clock>,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64, clock: Box<dyn Clock>) -> Self {
        // Global headroom is a generous multiple of one tenant's budget:
        // normal multi-tenant traffic never notices it, a bulk exporter hits
        // it immediately.
        Self {
            buckets: Mutex::new(HashMap::new()),
            global: Mutex::new(HashMap::new()),
            capacity: f64::from(capacity),
            refill_per_sec,
            global_capacity: f64::from(capacity) * 50.0,
            global_refill_per_sec: refill_per_sec * 50.0,
            max_buckets: 10_000,
            clock,
        }
    }

    /// Refills a bucket for elapsed time and takes one token if available.
    fn take(bucket: &mut Bucket, now: Instant, capacity: f64, refill: f64) -> bool {
        // saturating_duration_since keeps a non-monotonic clock from
        // producing a negative interval.
        let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill).min(capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Consumes one token. `false` means the caller is over budget — either
    /// this tenant's, or the global ceiling for this operation.
    pub fn allow(&self, tenant_id: &str, op: &'static str) -> bool {
        let now = self.clock.now();

        // Global ceiling first: it is the limit a hostile caller cannot
        // escape by inventing identifiers, so it is checked before any
        // per-tenant bookkeeping that such a caller could influence.
        {
            // A poisoned lock must not take the service down: recover the map
            // and keep enforcing. Failing open here is the worst outcome.
            let mut global = self.global.lock().unwrap_or_else(|e| e.into_inner());
            let b = global
                .entry(op)
                .or_insert(Bucket { tokens: self.global_capacity, last: now });
            if !Self::take(b, now, self.global_capacity, self.global_refill_per_sec) {
                return false;
            }
        }

        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if buckets.len() >= self.max_buckets {
            // First pass is lossless: a bucket at capacity is
            // indistinguishable from one that does not exist yet.
            let cap = self.capacity;
            let refill = self.refill_per_sec;
            buckets.retain(|_, b| {
                b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * refill < cap
            });

            // If that was not enough, drop the least recently used down to
            // half. This does hand those tenants a fresh bucket, but the
            // global ceiling above still binds, so the trade buys a hard
            // memory bound without opening a bypass.
            if buckets.len() >= self.max_buckets {
                let target = self.max_buckets / 2;
                let mut keys: Vec<_> = buckets.iter().map(|(k, b)| (b.last, k.clone())).collect();
                keys.sort_by_key(|(last, _)| *last);
                for (_, k) in keys.into_iter().take(buckets.len() - target) {
                    buckets.remove(&k);
                }
            }
        }

        let key = (tenant_id.to_owned(), op);
        let bucket = buckets
            .entry(key)
            .or_insert(Bucket { tokens: self.capacity, last: now });
        Self::take(bucket, now, self.capacity, self.refill_per_sec)
    }
}

/// Defaults sized for a real login path, not a benchmark: a burst covers a
/// user's several fields in one request, and the sustained rate is what a
/// human-driven system produces. A bulk exporter trips this immediately.
pub fn default_limiter() -> RateLimiter {
    RateLimiter::new(120, 20.0, Box::new(SystemClock))
}

#[allow(dead_code)]
fn assert_send_sync<T: Send + Sync>() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct FakeClock {
        base: Instant,
        offset: Mutex<Duration>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self { base: Instant::now(), offset: Mutex::new(Duration::ZERO) }
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.base + *self.offset.lock().unwrap()
        }
    }

    /// Shares one clock with the limiter so a test can advance time.
    struct SharedClock(std::sync::Arc<FakeClock>);

    impl Clock for SharedClock {
        fn now(&self) -> Instant {
            self.0.now()
        }
    }

    fn limiter(capacity: u32, refill: f64) -> (RateLimiter, std::sync::Arc<FakeClock>) {
        let clock = std::sync::Arc::new(FakeClock::new());
        let l = RateLimiter::new(capacity, refill, Box::new(SharedClock(clock.clone())));
        (l, clock)
    }

    fn advance(clock: &FakeClock, d: Duration) {
        *clock.offset.lock().unwrap() += d;
    }

    #[test]
    fn a_burst_within_capacity_is_allowed() {
        let (l, _c) = limiter(5, 1.0);
        for i in 0..5 {
            assert!(l.allow("t1", "decrypt_field"), "call {i} should be allowed");
        }
    }

    #[test]
    fn exceeding_capacity_is_refused() {
        let (l, _c) = limiter(5, 1.0);
        for _ in 0..5 {
            assert!(l.allow("t1", "decrypt_field"));
        }
        assert!(!l.allow("t1", "decrypt_field"), "the sixth call must trip the cap");
    }

    #[test]
    fn tokens_refill_over_time() {
        let (l, c) = limiter(2, 1.0);
        assert!(l.allow("t1", "decrypt_field"));
        assert!(l.allow("t1", "decrypt_field"));
        assert!(!l.allow("t1", "decrypt_field"));
        advance(&c, Duration::from_secs(1));
        assert!(l.allow("t1", "decrypt_field"), "one second buys one token");
    }

    #[test]
    fn refill_never_exceeds_capacity() {
        let (l, c) = limiter(3, 100.0);
        assert!(l.allow("t1", "op"));
        advance(&c, Duration::from_secs(3600));
        for _ in 0..3 {
            assert!(l.allow("t1", "op"));
        }
        assert!(!l.allow("t1", "op"), "an idle hour must not bank unlimited tokens");
    }

    #[test]
    fn one_tenant_cannot_exhaust_anothers_budget() {
        let (l, _c) = limiter(2, 1.0);
        assert!(l.allow("noisy", "op"));
        assert!(l.allow("noisy", "op"));
        assert!(!l.allow("noisy", "op"));
        assert!(l.allow("quiet", "op"), "tenants must not share a bucket");
    }

    #[test]
    fn operations_are_budgeted_separately() {
        let (l, _c) = limiter(1, 1.0);
        assert!(l.allow("t1", "decrypt_field"));
        assert!(!l.allow("t1", "decrypt_field"));
        assert!(l.allow("t1", "blind_index"), "a spent budget must not block a different op");
    }

    #[test]
    fn bucket_map_stays_bounded_against_invented_tenants() {
        let (mut l, _c) = limiter(4, 1000.0);
        l.max_buckets = 16;
        // No time passes, so nothing refills and lossless eviction alone
        // cannot help — LRU eviction is what holds the bound.
        for i in 0..500 {
            l.allow(&format!("tenant-{i}"), "op");
        }
        let n = l.buckets.lock().unwrap().len();
        assert!(n <= 16, "map grew to {n}");
    }

    #[test]
    fn a_global_ceiling_binds_a_caller_inventing_tenants() {
        // The T9 case: a compromised gateway holds a valid credential and
        // fabricates tenant ids to dodge per-tenant budgets. The global
        // ceiling is what stops the drain.
        let (l, _c) = limiter(2, 0.0); // global capacity = 100, no refill
        let mut allowed = 0;
        for i in 0..500 {
            if l.allow(&format!("invented-{i}"), "decrypt_field") {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 100, "the global ceiling must cap the total, got {allowed}");
    }

    #[test]
    fn limiter_is_send_and_sync() {
        assert_send_sync::<RateLimiter>();
    }
}
