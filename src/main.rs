//! `fnbr-xdp-fw`: carga el XDP, llena los mapas, adjunta a la interfaz y
//! corre el clasificador semántico + grafo de llamadas sobre los eventos.
//! Requiere root (sudo) para `run`. `selftest` no necesita root.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, HashMap, PerCpuArray, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Ebpf, Pod};
use clap::{Parser, Subcommand};

use fnbr_xdp_fw::callgraph::CallGraph;
use fnbr_xdp_fw::patterns::{self, DEFAULT_PATTERNS};
use fnbr_xdp_fw::semantic::{self, Verdict};
use fnbr_xdp_fw::wire::{Event, FlowKey, PatternRaw, STAT_NAMES, XDP_DROP};

#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodFlow(FlowKey);
// SAFETY: repr(C) plano, sin padding (4+4+2+2), sin punteros.
unsafe impl Pod for PodFlow {}
#[repr(transparent)]
#[derive(Clone, Copy)]
struct PodPattern(PatternRaw);
// SAFETY: repr(C) plano (u32 + [u8;32]), sin punteros.
unsafe impl Pod for PodPattern {}

static BPF_OBJ: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/xdp_firewall.bpf.o"));

#[derive(Parser)]
#[command(name = "fnbr-xdp-fw", version, about = "Firewall semántico XDP (texto en claro) — FNBR #4")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Carga y adjunta el XDP (requiere root).
    Run {
        #[arg(long, default_value = "lo")]
        iface: String,
        /// Puertos TCP a vigilar (src o dst).
        #[arg(long, default_value = "18080", value_delimiter = ',')]
        ports: Vec<u16>,
        /// Segundos a correr (0 = hasta Ctrl-C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,
        /// Lista blanca de herramientas MCP (si se da, tools/call fuera de lista = anomalía).
        #[arg(long, value_delimiter = ',')]
        allow_tools: Vec<String>,
        /// Modo nativo (driver) en vez de genérico/skb.
        #[arg(long)]
        native: bool,
    },
    /// Clasifica un texto con el clasificador semántico (sin root).
    Classify { text: String },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Classify { text } => {
            let pats = patterns::encode_all(DEFAULT_PATTERNS)?;
            println!("kernel_ref_match = {:?}", patterns::kernel_reference_match(text.as_bytes(), &pats));
            println!("semantic         = {:?}", semantic::classify(text.as_bytes()));
            Ok(())
        }
        Cmd::Run { iface, ports, seconds, allow_tools, native } => run(&iface, &ports, seconds, allow_tools, native),
    }
}

fn run(iface: &str, ports: &[u16], seconds: u64, allow_tools: Vec<String>, native: bool) -> Result<()> {
    let mut bpf = Ebpf::load(BPF_OBJ).context("cargando objeto BPF (¿root?)")?;

    {
        let mut wp: HashMap<_, u16, u8> =
            HashMap::try_from(bpf.map_mut("watch_ports").ok_or_else(|| anyhow!("falta watch_ports"))?)?;
        for p in ports {
            wp.insert(*p, 1, 0)?;
        }
    }
    {
        let mut pm: Array<_, PodPattern> =
            Array::try_from(bpf.map_mut("patterns").ok_or_else(|| anyhow!("falta patterns"))?)?;
        for (i, p) in patterns::encode_all(DEFAULT_PATTERNS)?.into_iter().enumerate() {
            pm.set(i as u32, PodPattern(p), 0)?;
        }
    }

    let prog: &mut Xdp = bpf
        .program_mut("fnbr_xdp_fw")
        .ok_or_else(|| anyhow!("falta programa fnbr_xdp_fw"))?
        .try_into()?;
    prog.load().context("el verificador rechazó el programa")?;
    let flags = if native { XdpFlags::DRV_MODE } else { XdpFlags::SKB_MODE };
    let _link = prog.attach(iface, flags).with_context(|| format!("attach XDP a {iface}"))?;
    println!(
        "[fnbr-xdp-fw] XDP adjuntado a {iface} ({}) vigilando puertos {ports:?}",
        if native { "driver" } else { "xdpgeneric/skb" }
    );

    let mut blocked: HashMap<_, PodFlow, u32> =
        HashMap::try_from(bpf.take_map("blocked").ok_or_else(|| anyhow!("falta blocked"))?)?;
    let stats: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf.take_map("stats").ok_or_else(|| anyhow!("falta stats"))?)?;
    let mut ring = RingBuf::try_from(bpf.take_map("events").ok_or_else(|| anyhow!("falta events"))?)?;

    let mut graph = if allow_tools.is_empty() {
        CallGraph::new()
    } else {
        CallGraph::with_tool_allowlist(allow_tools)
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = stop.clone();
        ctrlc::set_handler(move || s.store(true, Ordering::SeqCst))?;
    }
    let start = Instant::now();
    while !stop.load(Ordering::SeqCst) && (seconds == 0 || start.elapsed() < Duration::from_secs(seconds)) {
        let mut got = false;
        while let Some(item) = ring.next() {
            got = true;
            let Some(ev) = Event::from_bytes(&item) else { continue };
            let flow = ev.flow;
            let payload = ev.payload();
            if ev.action == XDP_DROP {
                println!(
                    "[KERNEL DROP] {} patrón #{} ({:?}) — flujo bloqueado",
                    flow.display(),
                    ev.pattern_id,
                    DEFAULT_PATTERNS.get(ev.pattern_id as usize)
                );
                graph.forget(&flow);
                continue;
            }
            // Semántico: ambas direcciones (la salida de una herramienta también
            // puede traer inyección). Grafo de llamadas: solo pedidos cliente→servidor.
            let verdict = semantic::classify(payload);
            let is_request = ports.contains(&flow.dport);
            let anomaly = if is_request { graph.observe(&flow, payload) } else { None };
            let reason = match (&verdict, &anomaly) {
                (Verdict::Malicious { reasons, .. }, _) => Some(format!("semántico {reasons:?}")),
                (_, Some(a)) => Some(format!("grafo {a:?}")),
                _ => None,
            };
            if let Some(r) = reason {
                blocked.insert(PodFlow(flow), 1, 0)?;
                blocked.insert(PodFlow(flow.reversed()), 1, 0)?;
                graph.forget(&flow);
                println!("[USER BLOCK] {} — {r} — siguientes segmentos se descartan en XDP", flow.display());
            } else if let Verdict::Suspicious { score, reasons } = verdict {
                println!("[SOSPECHOSO] {} score={score} {reasons:?} (pasa)", flow.display());
            } else {
                println!("[PASS] {} {}B", flow.display(), ev.payload_len);
            }
        }
        if !got {
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    let mut line = String::from("[stats]");
    for (i, name) in STAT_NAMES.iter().enumerate() {
        let v: u64 = stats.get(&(i as u32), 0).map(|pc| pc.iter().sum()).unwrap_or(0);
        line.push_str(&format!(" {name}={v}"));
    }
    println!("{line}");
    println!("[fnbr-xdp-fw] desadjuntando XDP de {iface}");
    Ok(())
}
