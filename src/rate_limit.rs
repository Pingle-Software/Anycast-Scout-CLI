use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::{Instant as TokioInstant, sleep_until};

#[derive(Debug)]
pub struct RateLimiter {
    min_interval: Duration,
    next_request: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            next_request: Mutex::new(Instant::now()),
        }
    }

    pub async fn wait(&self) {
        if self.min_interval.is_zero() {
            return;
        }

        let scheduled = {
            let mut next_request = self.next_request.lock().await;
            let now = Instant::now();
            let scheduled = (*next_request).max(now);
            *next_request = scheduled + self.min_interval;
            scheduled
        };

        let now = Instant::now();
        if scheduled > now {
            sleep_until(TokioInstant::from_std(scheduled)).await;
        }
    }
}
