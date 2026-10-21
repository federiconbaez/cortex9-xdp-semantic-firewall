//! Detector de anomalías en el grafo de llamadas JSON-RPC (MCP) por flujo.
//!
//! Modelo: cada flujo TCP es una sesión MCP sobre HTTP en claro. Se extrae
//! el campo `"method"` del prefijo y se valida contra una máquina de estados
//! mínima del protocolo MCP + una lista blanca opcional de herramientas.
//! Límite: si el JSON viene partido entre segmentos, o después de los 192 B
//! del prefijo, no se ve.

use std::collections::{HashMap, HashSet};

use crate::wire::FlowKey;

pub const KNOWN_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "prompts/list",
    "prompts/get",
    "completion/complete",
    "logging/setLevel",
    "notifications/cancelled",
    "notifications/progress",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    BeforeInitialize(String),
    UnknownMethod(String),
    ToolNotAllowed(String),
    ReInitialize,
}

#[derive(Default, Debug)]
struct Session {
    initialized: bool,
    calls: u32,
}

#[derive(Default, Debug)]
pub struct CallGraph {
    sessions: HashMap<FlowKey, Session>,
    tool_allowlist: Option<HashSet<String>>,
}

/// Extrae el valor de `"key":"valor"` de un fragmento JSON (sin parsear todo,
/// porque el prefijo puede estar truncado).
pub fn extract_str_field(payload: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(payload);
    let needle = format!("\"{key}\"");
    let pos = text.find(&needle)? + needle.len();
    let rest = text[pos..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

impl CallGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tool_allowlist<I: IntoIterator<Item = S>, S: Into<String>>(tools: I) -> Self {
        Self {
            sessions: HashMap::new(),
            tool_allowlist: Some(tools.into_iter().map(Into::into).collect()),
        }
    }

    /// Clave canónica: las dos direcciones del flujo son la misma sesión.
    fn canon(k: &FlowKey) -> FlowKey {
        let r = k.reversed();
        if (k.saddr, k.sport) <= (r.saddr, r.sport) {
            *k
        } else {
            r
        }
    }

    /// Observa un payload; devuelve Some(anomalía) si viola el modelo.
    pub fn observe(&mut self, flow: &FlowKey, payload: &[u8]) -> Option<Anomaly> {
        let method = extract_str_field(payload, "method")?;
        let s = self.sessions.entry(Self::canon(flow)).or_default();
        if !KNOWN_METHODS.contains(&method.as_str()) {
            return Some(Anomaly::UnknownMethod(method));
        }
        match method.as_str() {
            "initialize" => {
                if s.initialized {
                    return Some(Anomaly::ReInitialize);
                }
                s.initialized = true;
                None
            }
            "ping" | "notifications/cancelled" => None,
            m if !s.initialized => Some(Anomaly::BeforeInitialize(m.to_string())),
            "tools/call" => {
                s.calls += 1;
                if let Some(allow) = &self.tool_allowlist {
                    let name = extract_str_field(payload, "name").unwrap_or_default();
                    if !allow.contains(&name) {
                        return Some(Anomaly::ToolNotAllowed(name));
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn forget(&mut self, flow: &FlowKey) {
        self.sessions.remove(&Self::canon(flow));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fk() -> FlowKey {
        FlowKey { saddr: 1, daddr: 2, sport: 40000, dport: 18080 }
    }

    #[test]
    fn extracts_method_from_truncated_json() {
        let p = br#"POST /mcp HTTP/1.1\r\n\r\n{"jsonrpc":"2.0","id":1, "method" : "tools/list", "par"#;
        assert_eq!(extract_str_field(p, "method").as_deref(), Some("tools/list"));
        assert_eq!(extract_str_field(b"no json", "method"), None);
    }

    #[test]
    fn normal_session_has_no_anomalies() {
        let mut g = CallGraph::with_tool_allowlist(["weather"]);
        let f = fk();
        assert_eq!(g.observe(&f, br#"{"method":"initialize"}"#), None);
        assert_eq!(g.observe(&f.reversed(), br#"{"result":{}}"#), None);
        assert_eq!(g.observe(&f, br#"{"method":"notifications/initialized"}"#), None);
        assert_eq!(g.observe(&f, br#"{"method":"tools/list"}"#), None);
        assert_eq!(g.observe(&f, br#"{"method":"tools/call","params":{"name":"weather"}}"#), None);
    }

    #[test]
    fn call_before_initialize_is_anomalous() {
        let mut g = CallGraph::new();
        assert_eq!(
            g.observe(&fk(), br#"{"method":"tools/call","params":{"name":"x"}}"#),
            Some(Anomaly::BeforeInitialize("tools/call".into()))
        );
    }

    #[test]
    fn unknown_and_disallowed() {
        let mut g = CallGraph::with_tool_allowlist(["weather"]);
        let f = fk();
        g.observe(&f, br#"{"method":"initialize"}"#);
        assert_eq!(
            g.observe(&f, br#"{"method":"admin/exec"}"#),
            Some(Anomaly::UnknownMethod("admin/exec".into()))
        );
        assert_eq!(
            g.observe(&f, br#"{"method":"tools/call","params":{"name":"shell"}}"#),
            Some(Anomaly::ToolNotAllowed("shell".into()))
        );
        assert_eq!(g.observe(&f, br#"{"method":"initialize"}"#), Some(Anomaly::ReInitialize));
    }

    #[test]
    fn both_directions_share_session() {
        let mut g = CallGraph::new();
        let f = fk();
        g.observe(&f.reversed(), br#"{"method":"initialize"}"#);
        assert_eq!(g.observe(&f, br#"{"method":"tools/list"}"#), None);
        g.forget(&f);
        assert!(g.observe(&f, br#"{"method":"tools/list"}"#).is_some());
    }
}
