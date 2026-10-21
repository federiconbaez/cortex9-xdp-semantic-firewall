// Compila bpf/xdp_firewall.bpf.c con clang -target bpf y lo deja en OUT_DIR
// para incrustarlo en el binario con include_bytes_aligned!.
use std::{env, path::PathBuf, process::Command};

fn main() {
    let src = "bpf/xdp_firewall.bpf.c";
    println!("cargo:rerun-if-changed={src}");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("xdp_firewall.bpf.o");
    let arch_inc = format!("-I/usr/include/{}-linux-gnu", env::consts::ARCH);
    let status = Command::new(env::var("CLANG").unwrap_or_else(|_| "clang".into()))
        .args(["-O2", "-g", "-Wall", "-target", "bpf", &arch_inc, "-c", src, "-o"])
        .arg(&out)
        .status()
        .expect("no se pudo ejecutar clang (instalar: apt-get install clang libbpf-dev)");
    assert!(status.success(), "clang -target bpf falló compilando {src}");
}
