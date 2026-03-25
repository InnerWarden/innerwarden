//! Redis Streams reader - consumes events from the sensor's Redis stream.
//!
//! Used instead of JSONL file polling when `redis_url` is configured.
//! Uses XREAD with a consumer group so multiple consumers (agent, DNA, Shield)
//! can independently track their position in the stream.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{info, warn};

const DEFAULT_EVENTS_STREAM: &str = "innerwarden:events";
const DEFAULT_INCIDENTS_STREAM: &str = "innerwarden:incidents";

/// Configuration for the Redis stream reader.
#[derive(Debug, Clone)]
pub struct RedisReaderConfig {
    pub url: String,
    pub events_stream: String,
    pub incidents_stream: String,
    /// Consumer group name - each consumer type gets its own group.
    pub group: String,
    /// Consumer name within the group (usually the hostname or instance ID).
    pub consumer: String,
    /// Max entries to read per XREADGROUP call.
    pub batch_size: usize,
}

/// Reads events and incidents from Redis Streams.
pub struct RedisStreamReader {
    conn: redis::aio::MultiplexedConnection,
    config: RedisReaderConfig,
    /// Total events consumed.
    events_consumed: u64,
}

impl RedisStreamReader {
    pub async fn connect(config: RedisReaderConfig) -> Result<Self> {
        let client = redis::Client::open(config.url.as_str())
            .with_context(|| format!("invalid Redis URL: {}", config.url))?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .with_context(|| format!("failed to connect to Redis at {}", config.url))?;

        // Create consumer groups (idempotent - ignore error if already exists).
        for stream in [&config.events_stream, &config.incidents_stream] {
            let result: redis::RedisResult<()> = redis::cmd("XGROUP")
                .arg("CREATE")
                .arg(stream)
                .arg(&config.group)
                .arg("0") // start from beginning
                .arg("MKSTREAM")
                .query_async(&mut conn)
                .await;
            match result {
                Ok(()) => info!(stream, group = %config.group, "created consumer group"),
                Err(e) if e.to_string().contains("BUSYGROUP") => {
                    // Group already exists - fine
                }
                Err(e) => warn!(stream, error = %e, "failed to create consumer group"),
            }
        }

        info!(
            url = %config.url,
            group = %config.group,
            consumer = %config.consumer,
            "Redis stream reader connected"
        );

        Ok(Self {
            conn,
            config,
            events_consumed: 0,
        })
    }

    /// Read new events from the events stream.
    /// Returns deserialized events. Automatically ACKs consumed entries.
    pub async fn read_events<T: serde::de::DeserializeOwned>(&mut self) -> Result<Vec<T>> {
        self.read_stream(&self.config.events_stream.clone()).await
    }

    /// Read new incidents from the incidents stream.
    pub async fn read_incidents<T: serde::de::DeserializeOwned>(&mut self) -> Result<Vec<T>> {
        self.read_stream(&self.config.incidents_stream.clone())
            .await
    }

    async fn read_stream<T: serde::de::DeserializeOwned>(
        &mut self,
        stream: &str,
    ) -> Result<Vec<T>> {
        // XREADGROUP GROUP <group> <consumer> COUNT <n> STREAMS <stream> >
        let top_value: redis::Value = match redis::cmd("XREADGROUP")
            .arg("GROUP")
            .arg(&self.config.group)
            .arg(&self.config.consumer)
            .arg("COUNT")
            .arg(self.config.batch_size)
            .arg("STREAMS")
            .arg(stream)
            .arg(">") // only new messages
            .query_async(&mut self.conn)
            .await
        {
            Ok(v) => v,
            Err(e) => {
                if e.to_string().contains("NOGROUP") {
                    warn!(stream, "consumer group does not exist");
                    return Ok(Vec::new());
                }
                anyhow::bail!("XREADGROUP failed: {e}");
            }
        };

        // Nil response means no new messages
        let values = match top_value {
            redis::Value::Array(v) => v,
            redis::Value::Nil => return Ok(Vec::new()),
            _ => return Ok(Vec::new()),
        };

        let mut entries = Vec::new();
        let mut ids_to_ack = Vec::new();

        // Parse the XREADGROUP response: [[stream_name, [[id, [field, value, ...]], ...]]]
        for stream_result in &values {
            if let redis::Value::Array(ref stream_data) = stream_result {
                if stream_data.len() < 2 {
                    continue;
                }
                if let redis::Value::Array(ref messages) = stream_data[1] {
                    for msg in messages {
                        if let redis::Value::Array(ref msg_parts) = msg {
                            if msg_parts.len() < 2 {
                                continue;
                            }
                            // msg_parts[0] = id, msg_parts[1] = [field, value, ...]
                            let id = match &msg_parts[0] {
                                redis::Value::BulkString(b) => {
                                    String::from_utf8_lossy(b).to_string()
                                }
                                _ => continue,
                            };
                            if let redis::Value::Array(ref fields) = msg_parts[1] {
                                // Find the "data" field
                                for chunk in fields.chunks(2) {
                                    if chunk.len() == 2 {
                                        let key = match &chunk[0] {
                                            redis::Value::BulkString(b) => {
                                                String::from_utf8_lossy(b)
                                            }
                                            _ => continue,
                                        };
                                        if key == "data" {
                                            if let redis::Value::BulkString(ref data) = chunk[1] {
                                                match serde_json::from_slice::<T>(data) {
                                                    Ok(entry) => {
                                                        entries.push(entry);
                                                        ids_to_ack.push(id.clone());
                                                    }
                                                    Err(e) => {
                                                        warn!(
                                                            stream,
                                                            id, "failed to parse entry: {e}"
                                                        );
                                                        ids_to_ack.push(id.clone());
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ACK all consumed messages
        if !ids_to_ack.is_empty() {
            let mut cmd = redis::cmd("XACK");
            cmd.arg(stream).arg(&self.config.group);
            for id in &ids_to_ack {
                cmd.arg(id.as_str());
            }
            let _: redis::RedisResult<()> = cmd.query_async(&mut self.conn).await;
        }

        self.events_consumed += entries.len() as u64;
        Ok(entries)
    }

    pub fn events_consumed(&self) -> u64 {
        self.events_consumed
    }
}

/// Create a default reader config for the agent.
pub fn agent_config(url: &str, stream: Option<&str>) -> RedisReaderConfig {
    RedisReaderConfig {
        url: url.to_string(),
        events_stream: stream.unwrap_or(DEFAULT_EVENTS_STREAM).to_string(),
        incidents_stream: DEFAULT_INCIDENTS_STREAM.to_string(),
        group: "innerwarden-agent".to_string(),
        consumer: "agent-1".to_string(),
        batch_size: 500,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_config_defaults() {
        let cfg = agent_config("redis://127.0.0.1:6379", None);
        assert_eq!(cfg.events_stream, "innerwarden:events");
        assert_eq!(cfg.incidents_stream, "innerwarden:incidents");
        assert_eq!(cfg.group, "innerwarden-agent");
        assert_eq!(cfg.batch_size, 500);
    }
}
