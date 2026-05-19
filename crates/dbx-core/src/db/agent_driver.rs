use std::collections::VecDeque;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

pub const AGENT_PROTOCOL_VERSION: u32 = 1;
const RPC_TIMEOUT_SECS: u64 = 30;
const STARTUP_TIMEOUT_SECS: u64 = 15;
const STDERR_TAIL_LINES: usize = 20;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct AgentDriverClient {
    child: Child,
    stdin: Option<BufWriter<ChildStdin>>,
    stdout: Option<BufReader<ChildStdout>>,
    stderr_tail: Arc<Mutex<StderrTail>>,
    next_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentHandshake {
    pub protocol_version: u32,
    pub agent_protocol_version: u32,
    pub capabilities: Vec<String>,
}

impl AgentHandshake {
    pub fn supports(&self, capability: AgentCapability) -> bool {
        self.capabilities.iter().any(|value| value == capability.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCapability {
    Connect,
    TestConnection,
    Metadata,
    Query,
    PagedQuery,
    Transaction,
    Ddl,
}

impl AgentCapability {
    pub const ALL: [Self; 7] = [
        Self::Connect,
        Self::TestConnection,
        Self::Metadata,
        Self::Query,
        Self::PagedQuery,
        Self::Transaction,
        Self::Ddl,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::TestConnection => "test_connection",
            Self::Metadata => "metadata",
            Self::Query => "query",
            Self::PagedQuery => "paged_query",
            Self::Transaction => "transaction",
            Self::Ddl => "ddl",
        }
    }
}

struct StderrTail {
    lines: VecDeque<String>,
    capacity: usize,
}

impl Default for StderrTail {
    fn default() -> Self {
        Self::with_capacity(STDERR_TAIL_LINES)
    }
}

impl StderrTail {
    fn with_capacity(capacity: usize) -> Self {
        Self { lines: VecDeque::with_capacity(capacity), capacity }
    }

    fn push_line(&mut self, line: String) {
        if self.capacity == 0 {
            return;
        }
        while self.lines.len() >= self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line.trim_end().to_string());
    }

    fn snapshot(&self) -> String {
        self.lines.iter().filter(|line| !line.trim().is_empty()).cloned().collect::<Vec<_>>().join("\n")
    }
}

impl AgentDriverClient {
    /// Spawn a Java agent process and wait for it to signal readiness.
    ///
    /// The agent is started via `java -jar <jar_path>` with stdin/stdout piped.
    /// Blocks (async) until the agent writes `{"ready":true}` to stdout.
    pub async fn spawn(java_path: &str, jar_path: &str) -> Result<Self, String> {
        let mut command = Command::new(java_path);
        command.args(agent_java_args(jar_path)).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        remove_agent_proxy_env(&mut command);

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = command.spawn().map_err(|e| format!("Failed to spawn agent process: {e}"))?;

        let child_stdin = child.stdin.take().ok_or("Failed to capture agent stdin")?;
        let child_stdout = child.stdout.take().ok_or("Failed to capture agent stdout")?;
        let child_stderr = child.stderr.take().ok_or("Failed to capture agent stderr")?;

        let stdin = BufWriter::new(child_stdin);
        let mut stdout = BufReader::new(child_stdout);
        let stderr_tail = Arc::new(Mutex::new(StderrTail::default()));
        start_stderr_collector(child_stderr, stderr_tail.clone());

        // Wait for the agent to signal readiness with {"ready":true}
        let startup_result = tokio::time::timeout(
            Duration::from_secs(STARTUP_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                let line = read_agent_line(&mut stdout, "startup line")?;
                let v: Value = serde_json::from_str(line.trim())
                    .map_err(|e| format!("Invalid JSON from agent during startup: {e}"))?;
                if v.get("ready") != Some(&Value::Bool(true)) {
                    return Err(format!("Agent did not send ready signal, got: {line}"));
                }
                Ok(stdout)
            }),
        )
        .await;

        let ready_stdout = match startup_result {
            Ok(Ok(Ok(stdout))) => stdout,
            Ok(Ok(Err(e))) => {
                return Err(format_agent_process_error(
                    &e,
                    child_exit_status(&mut child),
                    &stderr_tail_snapshot(&stderr_tail),
                ));
            }
            Ok(Err(e)) => {
                return Err(format_agent_process_error(
                    &format!("Agent startup task failed: {e}"),
                    child_exit_status(&mut child),
                    &stderr_tail_snapshot(&stderr_tail),
                ));
            }
            Err(_) => {
                return Err(format_agent_process_error(
                    &format!("Agent startup timed out ({STARTUP_TIMEOUT_SECS}s)"),
                    child_exit_status(&mut child),
                    &stderr_tail_snapshot(&stderr_tail),
                ));
            }
        };

        Ok(Self { child, stdin: Some(stdin), stdout: Some(ready_stdout), stderr_tail, next_id: 0 })
    }

    /// Send a JSON-RPC 2.0 request and wait for the response.
    pub async fn call<T: DeserializeOwned + Send + 'static>(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<T, String> {
        self.next_id += 1;
        let id = self.next_id;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let request_line =
            serde_json::to_string(&request).map_err(|e| format!("Failed to serialize JSON-RPC request: {e}"))?;

        // Write request to stdin
        let write_result = {
            let writer = self.stdin.as_mut().ok_or("Agent stdin not available")?;
            writer
                .write_all(request_line.as_bytes())
                .map_err(|e| format!("Failed to write to agent stdin: {e}"))
                .and_then(|_| {
                    writer.write_all(b"\n").map_err(|e| format!("Failed to write newline to agent stdin: {e}"))
                })
                .and_then(|_| writer.flush().map_err(|e| format!("Failed to flush agent stdin: {e}")))
        };
        if let Err(e) = write_result {
            return Err(self.format_agent_process_error(&e));
        }

        // Read response from stdout (blocking, with timeout)
        let mut reader = self.stdout.take().ok_or("Agent stdout not available")?;

        let (returned_reader, result) = tokio::time::timeout(
            Duration::from_secs(RPC_TIMEOUT_SECS),
            tokio::task::spawn_blocking(move || {
                let line = match read_agent_line(&mut reader, "response") {
                    Ok(line) => line,
                    Err(e) => return (reader, Err(e)),
                };

                let resp: Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        return (reader, Err(format!("Invalid JSON response from agent: {e}")));
                    }
                };

                let result = if let Some(err) = resp.get("error") {
                    let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown agent error");
                    let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
                    Err(format!("Agent RPC error ({code}): {msg}"))
                } else if let Some(result_val) = resp.get("result") {
                    serde_json::from_value::<T>(result_val.clone())
                        .map_err(|e| format!("Failed to deserialize agent result: {e}"))
                } else {
                    Err(format!("Agent response missing both 'result' and 'error': {line}"))
                };

                (reader, result)
            }),
        )
        .await
        .map_err(|_| format!("Agent RPC call timed out ({RPC_TIMEOUT_SECS}s)"))?
        .map_err(|e| format!("Agent RPC task failed: {e}"))?;

        let _ = self.stdout.insert(returned_reader);
        result.map_err(|e| self.format_agent_process_error(&e))
    }

    pub async fn try_optional_handshake(&mut self, app_version: &str) -> Option<AgentHandshake> {
        match self.call::<AgentHandshake>("handshake", agent_handshake_params(app_version)).await {
            Ok(handshake) => {
                log::info!(
                    "[agent] handshake complete: protocol={}, agent_protocol={}, capabilities={:?}",
                    handshake.protocol_version,
                    handshake.agent_protocol_version,
                    handshake.capabilities
                );
                Some(handshake)
            }
            Err(err) if is_unsupported_handshake_error(&err) => {
                log::info!("[agent] handshake unsupported by this driver; continuing with legacy protocol");
                None
            }
            Err(err) => {
                log::warn!("[agent] handshake failed; continuing with legacy protocol: {err}");
                None
            }
        }
    }

    /// Send a shutdown message to the agent and wait for the process to exit.
    pub async fn shutdown(&mut self) {
        // Try to send a shutdown RPC; ignore errors if the agent is already gone
        let shutdown_result: Result<Value, String> = self.call("shutdown", Value::Null).await;
        if let Err(e) = &shutdown_result {
            log::warn!("Agent shutdown RPC failed: {e}");
        }

        // Drop stdin to signal EOF
        self.stdin.take();

        // Wait for the child to exit
        match self.child.wait() {
            Ok(status) => log::info!("Agent process exited with {status}"),
            Err(e) => log::warn!("Failed to wait for agent process: {e}"),
        }
    }

    /// Forcefully kill the agent process.
    pub fn kill(&mut self) {
        self.stdin.take();
        self.stdout.take();
        if let Err(e) = self.child.kill() {
            log::warn!("Failed to kill agent process: {e}");
        }
        // Reap the child to avoid zombie processes
        let _ = self.child.wait();
    }
}

pub fn agent_handshake_params(app_version: &str) -> Value {
    serde_json::json!({
        "appVersion": app_version,
        "supportedProtocolVersions": [AGENT_PROTOCOL_VERSION],
    })
}

pub fn is_unsupported_handshake_error(error: &str) -> bool {
    error.contains("Unknown method: handshake")
        || error.contains("Method not found: handshake")
        || error.contains("method not found: handshake")
}

fn agent_java_args(jar_path: &str) -> Vec<String> {
    [
        "-Dfile.encoding=UTF-8",
        "-Dsun.stdout.encoding=UTF-8",
        "-Dsun.stderr.encoding=UTF-8",
        "-Djava.net.useSystemProxies=false",
        "-Dhttp.proxyHost=",
        "-Dhttps.proxyHost=",
        "-DsocksProxyHost=",
        "-Doracle.net.disableOob=true",
        "-Doracle.jdbc.javaNetNio=false",
        "-XX:TieredStopAtLevel=1",
        "-XX:+UseSerialGC",
        "-jar",
        jar_path,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn remove_agent_proxy_env(command: &mut Command) {
    for key in agent_proxy_env_vars() {
        command.env_remove(key);
    }
}

fn agent_proxy_env_vars() -> &'static [&'static str] {
    &["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]
}

fn read_agent_line<R: BufRead>(reader: &mut R, context: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader.read_until(b'\n', &mut bytes).map_err(|e| format!("Failed to read {context} from agent: {e}"))?;
    if bytes.is_empty() {
        return Err(format!("Failed to read {context} from agent: end of stream"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn start_stderr_collector(stderr: ChildStderr, stderr_tail: Arc<Mutex<StderrTail>>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    log::warn!("[agent:stderr] {}", line.trim_end());
                    if let Ok(mut tail) = stderr_tail.lock() {
                        tail.push_line(line.clone());
                    }
                }
                Err(err) => {
                    log::warn!("[agent:stderr] failed to read stderr: {err}");
                    break;
                }
            }
        }
    });
}

fn child_exit_status(child: &mut Child) -> Option<String> {
    match child.try_wait() {
        Ok(Some(status)) => Some(status.to_string()),
        Ok(None) => None,
        Err(err) => Some(format!("status unavailable: {err}")),
    }
}

fn stderr_tail_snapshot(stderr_tail: &Arc<Mutex<StderrTail>>) -> StderrTail {
    let snapshot = stderr_tail.lock().map(|tail| tail.snapshot()).unwrap_or_default();
    let mut tail = StderrTail::with_capacity(STDERR_TAIL_LINES);
    for line in snapshot.lines() {
        tail.push_line(line.to_string());
    }
    tail
}

fn format_agent_process_error(base: &str, exit_status: Option<String>, stderr_tail: &StderrTail) -> String {
    let mut parts = vec![base.to_string()];
    if let Some(status) = exit_status {
        parts.push(format!("agent process exited with {status}"));
    }
    let stderr = stderr_tail.snapshot();
    if !stderr.is_empty() {
        parts.push(format!("recent stderr:\n{stderr}"));
    }
    parts.join(". ")
}

impl AgentDriverClient {
    fn format_agent_process_error(&mut self, base: &str) -> String {
        format_agent_process_error(base, child_exit_status(&mut self.child), &stderr_tail_snapshot(&self.stderr_tail))
    }
}

impl Drop for AgentDriverClient {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        agent_handshake_params, agent_java_args, agent_proxy_env_vars, format_agent_process_error,
        is_unsupported_handshake_error, read_agent_line, AgentCapability, AgentHandshake, StderrTail,
        AGENT_PROTOCOL_VERSION,
    };
    use std::io::Cursor;

    #[test]
    fn agent_java_args_include_oracle_network_compatibility_flags() {
        let args = agent_java_args("/tmp/dbx-agent-oracle.jar");

        assert!(args.iter().any(|arg| arg == "-Doracle.net.disableOob=true"));
        assert!(args.iter().any(|arg| arg == "-Doracle.jdbc.javaNetNio=false"));
    }

    #[test]
    fn agent_java_args_disable_ambient_proxy_settings() {
        let args = agent_java_args("/tmp/dbx-agent-opengauss.jar");

        assert!(args.iter().any(|arg| arg == "-Djava.net.useSystemProxies=false"));
        assert!(args.iter().any(|arg| arg == "-Dhttp.proxyHost="));
        assert!(args.iter().any(|arg| arg == "-Dhttps.proxyHost="));
        assert!(args.iter().any(|arg| arg == "-DsocksProxyHost="));
    }

    #[test]
    fn agent_process_environment_removes_common_proxy_variables() {
        let proxy_env_vars = agent_proxy_env_vars();

        for key in
            ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]
        {
            assert!(proxy_env_vars.contains(&key));
        }
    }

    #[test]
    fn decodes_non_utf8_agent_lines_lossily() {
        let mut reader =
            Cursor::new(vec![b'{', b'"', b'e', b'r', b'r', b'o', b'r', b'"', b':', 0xB2, 0xE2, b'}', b'\n']);

        let line = read_agent_line(&mut reader, "response").expect("line should be readable");

        assert_eq!(line, format!("{{\"error\":{}}}\n", "\u{fffd}\u{fffd}"));
    }

    #[test]
    fn formats_agent_process_error_with_exit_status_and_stderr_tail() {
        let mut stderr_tail = StderrTail::default();
        stderr_tail.push_line("java.lang.NoClassDefFoundError: org/apache/hive/jdbc/HiveDriver".to_string());
        stderr_tail.push_line("\tat com.dbx.agent.hive.HiveAgent.connect(HiveAgent.kt:21)".to_string());

        let message = format_agent_process_error(
            "Failed to read response from agent: end of stream",
            Some("exit status: 1".to_string()),
            &stderr_tail,
        );

        assert!(message.contains("Failed to read response from agent: end of stream"));
        assert!(message.contains("agent process exited with exit status: 1"));
        assert!(message.contains("recent stderr:"));
        assert!(message.contains("NoClassDefFoundError"));
        assert!(message.contains("HiveAgent.connect"));
    }

    #[test]
    fn stderr_tail_keeps_recent_lines_only() {
        let mut stderr_tail = StderrTail::with_capacity(3);
        stderr_tail.push_line("line 1".to_string());
        stderr_tail.push_line("line 2".to_string());
        stderr_tail.push_line("line 3".to_string());
        stderr_tail.push_line("line 4".to_string());

        assert_eq!(stderr_tail.snapshot(), "line 2\nline 3\nline 4");
    }

    #[test]
    fn builds_agent_handshake_request_params() {
        let params = agent_handshake_params("0.5.13");

        assert_eq!(params["appVersion"], "0.5.13");
        assert_eq!(params["supportedProtocolVersions"], serde_json::json!([AGENT_PROTOCOL_VERSION]));
    }

    #[test]
    fn decodes_agent_handshake_response() {
        let handshake: AgentHandshake = serde_json::from_value(serde_json::json!({
            "protocolVersion": 1,
            "agentProtocolVersion": 1,
            "capabilities": ["connect", "query", "metadata"]
        }))
        .unwrap();

        assert_eq!(handshake.protocol_version, 1);
        assert_eq!(handshake.agent_protocol_version, 1);
        assert_eq!(handshake.capabilities, vec!["connect", "query", "metadata"]);
    }

    #[test]
    fn defines_agent_protocol_capabilities() {
        assert_eq!(AgentCapability::Connect.as_str(), "connect");
        assert_eq!(AgentCapability::TestConnection.as_str(), "test_connection");
        assert_eq!(AgentCapability::Metadata.as_str(), "metadata");
        assert_eq!(AgentCapability::Query.as_str(), "query");
        assert_eq!(AgentCapability::PagedQuery.as_str(), "paged_query");
        assert_eq!(AgentCapability::Transaction.as_str(), "transaction");
        assert_eq!(AgentCapability::Ddl.as_str(), "ddl");
        assert_eq!(AgentCapability::ALL.len(), 7);
    }

    #[test]
    fn checks_handshake_capability_support() {
        let handshake = AgentHandshake {
            protocol_version: AGENT_PROTOCOL_VERSION,
            agent_protocol_version: AGENT_PROTOCOL_VERSION,
            capabilities: vec!["connect".to_string(), "metadata".to_string()],
        };

        assert!(handshake.supports(AgentCapability::Connect));
        assert!(handshake.supports(AgentCapability::Metadata));
        assert!(!handshake.supports(AgentCapability::Query));
    }

    #[test]
    fn treats_unknown_handshake_method_as_compatible_fallback() {
        assert!(is_unsupported_handshake_error("Agent RPC error (-1): Unknown method: handshake"));
        assert!(!is_unsupported_handshake_error("Agent RPC error (-1): Connection failed"));
    }
}
