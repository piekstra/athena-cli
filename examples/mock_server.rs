//! The loopback mock of athenahealth the tests use, as a server to dogfood
//! against: `cargo run --example mock_server -- [PORT]`. It prints its FHIR
//! base URL and serves synthetic patients only.
//!
//! ```text
//! athena config set practice mock --env custom --fhir-base <URL> --client-id mock-client
//! athena auth login --org mock --label test
//! curl -X POST 'http://127.0.0.1:<PORT>/__mock/mode?set=revoked'   # error paths
//! ```

#[path = "../tests/support/mock.rs"]
mod mock;

fn main() {
    let port = std::env::args()
        .nth(1)
        .map(|p| p.parse().expect("PORT is a number"))
        .unwrap_or(0);
    let server = mock::Mock::start(port);
    println!("{}", server.fhir_base());
    eprintln!(
        "mock athenahealth on {} (client id `{}`); modes: POST {}/__mock/mode?set=normal|expired|revoked|deny|down|degraded|forbidden, POST {}/__mock/expire",
        server.origin(),
        mock::CLIENT_ID,
        server.origin(),
        server.origin()
    );
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
