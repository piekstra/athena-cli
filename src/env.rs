//! athenahealth's two API environments, and a third for anything else (the
//! loopback mock, or a customer-run FHIR server named by its base URL).

use serde::{Deserialize, Serialize};

/// athenahealth's Preview environment: the sandbox and its synthetic patients.
pub const PREVIEW_API: &str = "https://api.preview.platform.athenahealth.com";
/// athenahealth's Production environment: real practices and real records.
pub const PRODUCTION_API: &str = "https://api.platform.athenahealth.com";

/// Which environment a practice profile signs in against. A client id is
/// issued per environment, so each needs its own registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Preview,
    #[default]
    Production,
    /// A FHIR base given in full (`--fhir-base`), with its own client id.
    Custom,
}

impl Environment {
    /// The API host, for the two athenahealth environments.
    pub const fn api_base(self) -> Option<&'static str> {
        match self {
            Environment::Preview => Some(PREVIEW_API),
            Environment::Production => Some(PRODUCTION_API),
            Environment::Custom => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Environment::Preview => "preview",
            Environment::Production => "production",
            Environment::Custom => "custom",
        }
    }

    /// Whether this is one of athenahealth's own environments, whose sign-in
    /// page carries the "Log in with athenahealth" button.
    pub const fn is_athenahealth(self) -> bool {
        !matches!(self, Environment::Custom)
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
