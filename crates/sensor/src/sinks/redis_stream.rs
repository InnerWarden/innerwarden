use anyhow::{Context, Result};
use innerwarden_core::{event::Event, incident::Incident};
use redis::AsyncCommands;
use tracing::{info, warn};

/// Default Redis stream names.
const DEFAULT_EVENTS_STREAM: &str = "innerwarden:events";
const DEFAULT_INCIDENTS_STREAM: &str = "innerwarden:incidents";

/// Configuration for the Redis stream sink.
#[derive(Debug, Clone)]
pub struct RedisStreamConfig {
    pub url: String,
    pub events_stream: String,
    pub incidents_stream: String,
    pub maxlen: usize,
}

impl RedisStreamConfig {
    pub fn new(url: &str, stream: Option<&str>, maxlen: usize) -> Self {
        Self {
            url: url.to_string(),
            events_stream: stream.unwrap_or(DEFAULT_EVENTS_STREAM).to_string(),
            incidents_stream: DEFAULT_INCIDENTS_STREAM.to_string(),
            maxlen,
        }
    }
}

/// Publishes events and incidents to Redis Streams via XADD with MAXLEN.
pub struct RedisStreamWriter {
    conn: redis::aio::MultiplexedConnection,
    config: RedisStreamConfig,
    /// Events published since last log.
    events_count: u64,
}

impl RedisStreamWriter {
    pub async fn connect(config: RedisStreamConfig) -> Result<Self> {
        let client = redis::Client::open(config.url.as_str())
            .with_context(|| format!("invalid Redis URL: {}", config.url))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("failed to connect to Redis at {}", config.url))?;

        info!(
            url = %config.url,
            events_stream = %config.events_stream,
            incidents_stream = %config.incidents_stream,
            maxlen = config.maxlen,
            "Redis stream sink connected"
        );

        Ok(Self {
            conn,
            config,
            events_count: 0,
        })
    }

    /// Publish an event to the events stream.
    pub async fn write_event(&mut self, event: &Event) -> Result<()> {
        let json = serde_json::to_string(event)?;

        redis::cmd("XADD")
            .arg(&self.config.events_stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(self.config.maxlen)
            .arg("*")
            .arg("data")
            .arg(&json)
            .query_async::<()>(&mut self.conn)
            .await
            .with_context(|| "XADD event failed")?;

        self.events_count += 1;
        Ok(())
    }

    /// Publish an incident to the incidents stream.
    pub async fn write_incident(&mut self, incident: &Incident) -> Result<()> {
        let json = serde_json::to_string(incident)?;

        redis::cmd("XADD")
            .arg(&self.config.incidents_stream)
            .arg("MAXLEN")
            .arg("~")
            .arg(self.config.maxlen)
            .arg("*")
            .arg("data")
            .arg(&json)
            .query_async::<()>(&mut self.conn)
            .await
            .with_context(|| "XADD incident failed")?;

        Ok(())
    }

    /// How many events have been published.
    pub fn events_published(&self) -> u64 {
        self.events_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let cfg = RedisStreamConfig::new("redis://127.0.0.1:6379", None, 50000);
        assert_eq!(cfg.events_stream, "innerwarden:events");
        assert_eq!(cfg.incidents_stream, "innerwarden:incidents");
        assert_eq!(cfg.maxlen, 50000);
    }

    #[test]
    fn config_custom_stream() {
        let cfg = RedisStreamConfig::new("redis://localhost", Some("custom:events"), 10000);
        assert_eq!(cfg.events_stream, "custom:events");
        assert_eq!(cfg.maxlen, 10000);
    }
}
