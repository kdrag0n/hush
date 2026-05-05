use quinn_proto::{
    RttEstimator,
    congestion::{Controller, ControllerFactory, ControllerMetrics},
};
use std::{any::Any, sync::Arc, time::Instant};

const DEFAULT_SEND_WINDOW_PACKETS: u64 = 32;
const INITIAL_SSTHRESH_PACKETS: u64 = 2;
const MIN_SSTHRESH_PACKETS: u64 = 2;
const FAST_RESEND_THRESHOLD: u64 = 2;

#[derive(Debug, Clone)]
pub struct KcpConfig {
    send_window_packets: u64,
    fast_resend_threshold: u64,
    no_congestion_window: bool,
}

impl KcpConfig {
    pub fn fast() -> Self {
        Self {
            send_window_packets: DEFAULT_SEND_WINDOW_PACKETS,
            fast_resend_threshold: FAST_RESEND_THRESHOLD,
            no_congestion_window: true,
        }
    }

    #[cfg(test)]
    fn normal_for_test() -> Self {
        Self {
            send_window_packets: DEFAULT_SEND_WINDOW_PACKETS,
            fast_resend_threshold: FAST_RESEND_THRESHOLD,
            no_congestion_window: false,
        }
    }
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self::fast()
    }
}

impl ControllerFactory for KcpConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(KcpController::new(self, now, current_mtu))
    }
}

#[derive(Debug, Clone)]
struct KcpController {
    config: Arc<KcpConfig>,
    current_mtu: u64,
    cwnd_packets: u64,
    ssthresh_packets: u64,
    incr_bytes: u64,
    recovery_start_time: Instant,
}

impl KcpController {
    fn new(config: Arc<KcpConfig>, now: Instant, current_mtu: u16) -> Self {
        let current_mtu = u64::from(current_mtu);
        Self {
            config,
            current_mtu,
            cwnd_packets: 1,
            ssthresh_packets: INITIAL_SSTHRESH_PACKETS,
            incr_bytes: current_mtu,
            recovery_start_time: now,
        }
    }

    fn send_window(&self) -> u64 {
        self.config.send_window_packets * self.current_mtu
    }

    fn cwnd(&self) -> u64 {
        self.cwnd_packets.max(1) * self.current_mtu
    }

    fn min_ssthresh(&self) -> u64 {
        MIN_SSTHRESH_PACKETS
    }
}

impl Controller for KcpController {
    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        _bytes: u64,
        app_limited: bool,
        _rtt: &RttEstimator,
    ) {
        if self.config.no_congestion_window || app_limited || sent <= self.recovery_start_time {
            return;
        }

        if self.cwnd_packets < self.ssthresh_packets {
            self.cwnd_packets += 1;
            self.incr_bytes += self.current_mtu;
        } else {
            self.incr_bytes = self.incr_bytes.max(self.current_mtu);
            self.incr_bytes += (self.current_mtu * self.current_mtu) / self.incr_bytes;
            self.incr_bytes += self.current_mtu / 16;

            if (self.cwnd_packets + 1) * self.current_mtu <= self.incr_bytes {
                self.cwnd_packets = self.incr_bytes.div_ceil(self.current_mtu);
            }
        }

        if self.cwnd_packets > self.config.send_window_packets {
            self.cwnd_packets = self.config.send_window_packets;
            self.incr_bytes = self.send_window();
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if self.config.no_congestion_window || sent <= self.recovery_start_time {
            return;
        }

        self.recovery_start_time = now;
        if is_persistent_congestion || lost_bytes > 0 {
            let prior = self.cwnd_packets.max(1);
            self.ssthresh_packets = (prior / 2).max(self.min_ssthresh());
            self.cwnd_packets = 1;
            self.incr_bytes = self.current_mtu;
        } else {
            let in_flight_packets = self.cwnd_packets.max(1);
            self.ssthresh_packets = (in_flight_packets / 2).max(self.min_ssthresh());
            self.cwnd_packets = self.ssthresh_packets + self.config.fast_resend_threshold;
            self.incr_bytes = self.cwnd();
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = u64::from(new_mtu);
        self.incr_bytes = self.incr_bytes.max(self.current_mtu);
    }

    fn window(&self) -> u64 {
        if self.config.no_congestion_window {
            self.send_window()
        } else {
            self.cwnd().min(self.send_window()).max(self.current_mtu)
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.ssthresh = Some(self.ssthresh_packets * self.current_mtu);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        if self.config.no_congestion_window {
            self.send_window()
        } else {
            self.current_mtu
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::congestion::ControllerFactory;
    use std::sync::Arc;

    #[test]
    fn fast_mode_uses_fixed_kcp_send_window() {
        let now = Instant::now();
        let mut controller = Arc::new(KcpConfig::fast()).build(now, 1200);

        assert_eq!(controller.initial_window(), 32 * 1200);
        assert_eq!(controller.window(), 32 * 1200);
        controller.on_congestion_event(now, now, true, 1200);
        assert_eq!(controller.window(), 32 * 1200);
    }

    #[test]
    fn normal_mode_falls_back_to_one_packet_on_loss() {
        let now = Instant::now();
        let mut controller = Arc::new(KcpConfig::normal_for_test()).build(now, 1200);

        assert_eq!(controller.window(), 1200);
        controller.on_congestion_event(now, now + std::time::Duration::from_millis(1), false, 1200);
        assert_eq!(controller.window(), 1200);
        assert_eq!(controller.metrics().ssthresh, Some(2 * 1200));
    }
}
