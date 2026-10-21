//! Lado espacio de usuario del firewall semántico XDP de FNBR.
//!
//! - [`wire`]: estructuras `#[repr(C)]` idénticas a las del programa BPF.
//! - [`patterns`]: normalización de patrones que se cargan en el mapa BPF.
//! - [`semantic`]: clasificador heurístico de inyección de prompts sobre el
//!   prefijo en claro que el kernel manda por el ring buffer.
//! - [`callgraph`]: detector de anomalías en la secuencia de métodos JSON-RPC
//!   (MCP) de cada flujo.
//!
//! Todo lo de este crate se prueba sin root. Cargar el XDP sí requiere root.

pub mod callgraph;
pub mod patterns;
pub mod semantic;
pub mod wire;
