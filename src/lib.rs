//! `athena`: a patient's or caregiver's own records from athenahealth
//! practices, through athenahealth's patient-access SMART on FHIR (R4) API.
//!
//! The modules are written so they can move into the shared medical crates
//! (`pk-med-smart`, `pk-med-fhir`, `pk-med-records`) once those are tagged:
//! [`oauth`] and [`smart`] are the sign-in, [`fhir`] the read client,
//! [`stream`] the `records-stream/v1` writer. What is athenahealth's alone
//! (its environments, its endpoint directory, its button page) stays in
//! [`env`], [`directory`] and [`login`].

pub mod cli;
pub mod config;
pub mod directory;
pub mod documents;
pub mod env;
pub mod export;
pub mod fhir;
pub mod http;
pub mod login;
pub mod oauth;
pub mod session;
pub mod smart;
pub mod stream;

/// The binary's name: keychain service suffix, config directory, user agent.
pub const BIN: &str = "athena";
/// This build's version, sent as the user agent and written to every stream.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Where releases come from.
pub const REPO: &str = "piekstra/athena-cli";

/// Seconds since the Unix epoch.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}
