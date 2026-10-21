use fnbr_xdp_fw::callgraph::CallGraph;
use fnbr_xdp_fw::wire::FlowKey;
fn main() {
    let f = FlowKey { saddr: 0x0100007f, daddr: 0x0100007f, sport: 40000, dport: 18181 };
    let mut g = CallGraph::with_tool_allowlist(["weather"]);
    let init = br#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{}}"#;
    println!("init -> {:?}", g.observe(&f, init));
    let hdr = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:18181\r\nContent-Type: application/json\r\nContent-Length: 999\r\n\r\n";
    let body = r#"{"jsonrpc":"2.0","id":"s1-x-2","method":"tools/call","params":{"name":"weather","arguments":{"city":"Rosario"}}}"#;
    let full = format!("{hdr}{body}");
    let i = full.find("\"name\":\"weather\"").unwrap();
    for cut in [full.len(), i + 16, i + 15, i + 10, i + 8, i + 3] {
        let p = &full.as_bytes()[..cut.min(full.len())];
        let mut g2 = CallGraph::with_tool_allowlist(["weather"]);
        g2.observe(&f, init);
        println!("prefijo {cut:3} B (fin: {:?}) -> {:?}", String::from_utf8_lossy(&p[p.len().saturating_sub(12)..]), g2.observe(&f, p));
    }
}
