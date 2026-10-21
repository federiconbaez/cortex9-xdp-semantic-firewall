.PHONY: build test clippy demo bpf clean
build:
	cargo build --release
bpf:  ## compila solo el objeto BPF (también lo hace build.rs)
	clang -O2 -g -Wall -target bpf -I/usr/include/$$(uname -m)-linux-gnu -c bpf/xdp_firewall.bpf.c -o target/xdp_firewall.bpf.o
test:
	cargo test
clippy:
	cargo clippy --all-targets -- -D warnings
demo:  ## requiere sudo: XDP real en lo + fixture TCP
	bash scripts/demo.sh
clean:
	cargo clean
