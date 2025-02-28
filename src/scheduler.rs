use std::sync::atomic::AtomicU64;
use tokio::time::Duration;

pub struct Scheduler {
    offset_timer: u64,
    interval: u64,
    counter: AtomicU64
}

impl Scheduler {
    pub fn new(offset_timer: u64, interval: u64) -> Self {
        Self {
            offset_timer,
            interval,
            counter: AtomicU64::new(0)
        }
    }

    pub fn get_offset(&self) -> Duration {
        Duration::from_secs(self.counter.fetch_add(self.offset_timer, std::sync::atomic::Ordering::Relaxed))
    }
    pub fn get_interval(&self) -> Duration {
        Duration::from_secs(self.interval)
    }
}

