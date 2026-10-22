# fnbr-xdp-semantic-firewall

> **Status: experimental research code. Its value threshold FAILED (see Audit status). Do not use it as a security control.**
> Spanish documentation: [`README.es.md`](README.es.md), [`LIMITES.md`](LIMITES.md), [`VERIFICADO.md`](VERIFICADO.md).

## What it is

An experiment in inspecting plaintext MCP/HTTP payloads in the XDP data path (eBPF + Rust/[aya](https://aya-rs.dev)) and dropping flows that look like prompt injection or anomalous MCP call sequences.

- **Kernel (`bpf/xdp_firewall.bpf.c`)**: parses Eth → IPv4 → TCP on watched ports. It copies up to 256 B of the payload and does case-insensitive matching against up to 8 literal patterns (≤ 32 B each) using `bpf_loop`. On a match it blocks the flow and returns `XDP_DROP`. It sends up to 192 B of the payload prefix to a ring buffer.
- **User space (`fnbr-xdp-fw`)**: a heuristic text classifier (normalisation plus scoring) and a per-flow MCP state machine. Either one can add a flow to the kernel `blocked` map.
- Known limits (see `LIMITES.md`):
  - It is blind to TLS.
  - There is no TCP reassembly, so a literal split across segments is missed.
  - It does not see MCP over stdio.
  - It sends no RST: the connection hangs until the client times out.
  - It was only tested in `xdpgeneric` mode on `lo`, so line-rate performance is **not measured**.
  - There is a known bug when a tool name is cut at byte 192.

## Build and test

Requirements: Linux, Rust ≥ 1.85, `clang`, `libbpf-dev` (headers). Root is needed only for the demo and the experiment.

```bash
cargo build --release      # build.rs compiles bpf/xdp_firewall.bpf.c with clang -target bpf
cargo test --release       # 19 unit tests, no root needed
cargo clippy --all-targets -- -D warnings
sudo bash scripts/demo.sh  # real XDP on lo + plaintext TCP fixture
bash scripts/experimento-valor.sh   # value experiment (needs sudo, nftables, python3)
```

## Audit status

The internal audit was done by the same team (AI agents working for the author). It is **not** an independent third-party audit. It is summarised from [`AUDIT-valor.md`](AUDIT-valor.md) (audit commit `77180b5`, experiment commit `43ffd0b`).

**Verdict: FAILS threshold #4. Value not demonstrated.**

The threshold had two parts, both measured on the same corpus: XDP must block strictly more attacks than the baseline, **and** its false-positive rate must satisfy FPR_XDP ≤ FPR_baseline + 0.02. Each seed had 234 attacks and 220 benign sessions, over 5 seeds.

Results with the `minimo` profile (96-byte headers, the case most favourable to XDP):

| | XDP | nftables (real) | string `--icase` (emulated) |
|---|---|---|---|
| Attacks blocked | 5.1–7.7 % | 1.3–6.0 % | 41.9–47.4 % |
| False-positive rate | 9.1–16.8 % | 0.5–3.6 % | 19.5–22.3 % |

- **Against nftables:** XDP blocks more attacks on all 5 seeds (+0.9 to +3.8 points). Its FPR, however, exceeds the 2-point tolerance by 5.3–13.9 points. → **Fails on FPR.**
- **Against the emulated string match:** XDP's FPR is lower, but it blocks 36.8–41.5 points fewer attacks. → **Fails on attacks.**
- **With realistic headers** (`streamable` profile, 263 B), XDP blocks 0 % on every seed.
- Every attack XDP blocked came from the kernel literal layer. The MCP call-graph "detections" (100 % in the `grafo` family) happen *after* the request has been delivered, so they do not count as blocks. They also drop to 0 % with realistic headers.
- Reproducibility: the audit re-ran the experiment on a separate clone and got per-seed results identical to the original. 19/19 tests pass and clippy is clean. Latency is p50 43–47 µs and p99 329–372 µs on a shared VM. That figure is noisy and not part of the threshold.
- Caveats: the `xt_string` baseline is an emulation, not the kernel module, and there is no segmentation on `lo`. The nftables baseline is weak (fixed-offset prefix matching).

## Repository notes

- `experimentos/valor/corpus/*.jsonl` (≈ 380 KB each) are **synthetic** attack and benign MCP requests. Attack strings such as `cat ~/.ssh/id_rsa` are payload text only. The targets are documentation values (`*.example`, 203.0.113.7, 198.51.100.9) plus the public service name `webhook.site`, which appears only as text. No real requests are sent outside `lo`.
- `experimentos/valor/resultados/crudo.tar.xz` (≈ 730 KB) contains the raw logs of the experiment.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

**Exception:** the eBPF program `bpf/xdp_firewall.bpf.c` is licensed **GPL-2.0** (`SPDX-License-Identifier: GPL-2.0`, `LICENSE[] = "GPL"`), because the kernel requires a GPL-compatible license for the BPF helpers it uses. `build.rs` compiles it, and `include_bytes_aligned!` **embeds the compiled object in the `fnbr-xdp-fw` binary**. Anyone distributing that binary should also comply with GPL-2.0 for the embedded eBPF object (its source is `bpf/xdp_firewall.bpf.c`). The Rust user-space code is MIT OR Apache-2.0.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above (except contributions to `bpf/`, which are GPL-2.0), without any additional terms or conditions.
