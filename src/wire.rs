//! Estructuras compartidas con `bpf/xdp_firewall.bpf.c`. Deben coincidir byte a byte.

pub const SCAN_LEN: usize = 256;
pub const PAT_MAX_LEN: usize = 32;
pub const MAX_PATTERNS: usize = 8;
pub const EVT_PREFIX: usize = 192;

pub const XDP_DROP: u32 = 1;
pub const XDP_PASS: u32 = 2;

/// Índices del mapa `stats` (enum stat_idx en C).
pub const STAT_NAMES: [&str; 6] = [
    "seen",
    "watched",
    "drop_pattern",
    "drop_blocked",
    "pass",
    "events_lost",
];

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FlowKey {
    /// IPv4 en orden de red, tal cual viene en el paquete.
    pub saddr: u32,
    pub daddr: u32,
    /// Puertos en orden de host (el BPF hace ntohs).
    pub sport: u16,
    pub dport: u16,
}

impl FlowKey {
    pub fn reversed(&self) -> Self {
        Self {
            saddr: self.daddr,
            daddr: self.saddr,
            sport: self.dport,
            dport: self.sport,
        }
    }

    pub fn display(&self) -> String {
        let s = std::net::Ipv4Addr::from(u32::from_be(self.saddr));
        let d = std::net::Ipv4Addr::from(u32::from_be(self.daddr));
        format!("{s}:{} -> {d}:{}", self.sport, self.dport)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PatternRaw {
    pub len: u32,
    pub bytes: [u8; PAT_MAX_LEN],
}

impl Default for PatternRaw {
    fn default() -> Self {
        Self {
            len: 0,
            bytes: [0; PAT_MAX_LEN],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub flow: FlowKey,
    pub payload_len: u32,
    pub copied: u32,
    pub pattern_id: i32,
    pub action: u32,
    pub prefix: [u8; EVT_PREFIX],
}

impl Event {
    /// Decodifica un registro del ring buffer. Devuelve None si el tamaño no coincide.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < std::mem::size_of::<Event>() {
            return None;
        }
        // SAFETY: Event es repr(C), Copy, sin punteros; read_unaligned tolera cualquier alineación.
        Some(unsafe { std::ptr::read_unaligned(b.as_ptr() as *const Event) })
    }

    pub fn payload(&self) -> &[u8] {
        let n = (self.copied as usize).min(EVT_PREFIX);
        &self.prefix[..n]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_c() {
        assert_eq!(std::mem::size_of::<FlowKey>(), 12);
        assert_eq!(std::mem::size_of::<PatternRaw>(), 4 + PAT_MAX_LEN);
        assert_eq!(std::mem::size_of::<Event>(), 12 + 16 + EVT_PREFIX);
    }

    #[test]
    fn event_roundtrip() {
        let mut e = Event {
            flow: FlowKey {
                saddr: u32::to_be(0x7f000001),
                daddr: u32::to_be(0x7f000001),
                sport: 5555,
                dport: 18080,
            },
            payload_len: 5,
            copied: 5,
            pattern_id: -1,
            action: XDP_PASS,
            prefix: [0; EVT_PREFIX],
        };
        e.prefix[..5].copy_from_slice(b"hello");
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(&e as *const _ as *const u8, std::mem::size_of::<Event>())
        };
        let d = Event::from_bytes(bytes).unwrap();
        assert_eq!(d.payload(), b"hello");
        assert_eq!(d.flow.display(), "127.0.0.1:5555 -> 127.0.0.1:18080");
        assert_eq!(d.flow.reversed().reversed(), d.flow);
        assert!(Event::from_bytes(&bytes[..10]).is_none());
    }
}
