use quinn::SendStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamPriority {
    Shell,
    Forward,
    FileCopy,
}

impl StreamPriority {
    pub const fn value(self) -> i32 {
        match self {
            Self::Shell => 20,
            Self::Forward => 10,
            Self::FileCopy => -10,
        }
    }
}

pub fn set_stream_priority(send: &SendStream, priority: StreamPriority) {
    if let Err(err) = send.set_priority(priority.value()) {
        tracing::debug!(%err, ?priority, "failed to set stream priority");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_priority_order_matches_interactive_policy() {
        assert!(StreamPriority::Shell.value() > StreamPriority::Forward.value());
        assert!(StreamPriority::Forward.value() > StreamPriority::FileCopy.value());
    }
}
