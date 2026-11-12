//! The request seam for what athena sends itself: token revocation and the
//! directory download. Sign-in and FHIR reads go through `pk_med_smart` and
//! `pk_med_fhir` over `pk_cli_http::BlockingTransport`.

use pk_cli_core::transport::{percent_encode, HttpRequest, HttpResponse, Transport};
use pk_cli_core::CliError;

use crate::{BIN, VERSION};

/// One request, one answer. A redirect is an answer like any other: nothing
/// here follows one, so a bearer token never leaves the host it was sent to.
pub trait Http {
    fn call(&self, request: HttpRequest) -> Result<HttpResponse, CliError>;
}

impl<T: Transport> Http for T {
    fn call(&self, request: HttpRequest) -> Result<HttpResponse, CliError> {
        pk_cli_core::block_on(self.send(request))
    }
}

/// A request carrying the family's `User-Agent: athena/<version>`.
pub fn request(method: &str, url: &str) -> HttpRequest {
    HttpRequest::new(method, url).user_agent(BIN, VERSION)
}

/// An `application/x-www-form-urlencoded` body.
pub fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{}={}", percent_encode(name), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `scheme://host[:port]`, lower-cased, or `None` for a URL without a scheme
/// or with userinfo (which no URL athena sends a token to may carry).
pub fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

/// Whether two URLs share an origin. A token for one is sent to the other
/// only when this holds.
pub fn same_origin(a: &str, b: &str) -> bool {
    matches!((origin(a), origin(b)), (Some(x), Some(y)) if x == y)
}

/// The value of a response header, case-insensitively.
pub fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response.header_value(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_compare_scheme_host_and_port() {
        assert!(same_origin(
            "https://api.platform.athenahealth.com/fhir/r4",
            "https://API.platform.athenahealth.com/fhir/r4/Binary/x?y=1"
        ));
        assert!(!same_origin(
            "https://api.platform.athenahealth.com/fhir/r4",
            "https://api.preview.platform.athenahealth.com/fhir/r4"
        ));
        assert!(!same_origin(
            "http://127.0.0.1:8080/fhir",
            "http://127.0.0.1:8081/fhir"
        ));
        assert!(!same_origin(
            "https://api.platform.athenahealth.com/fhir/r4",
            // Split so the personal-data scan does not read it as an email.
            concat!("https://user", "@api.platform.athenahealth.com/fhir/r4")
        ));
        assert!(!same_origin("Binary/123", "Binary/123"));
    }

    #[test]
    fn a_form_body_is_percent_encoded() {
        assert_eq!(
            form(&[("scope", "openid patient/Patient.read"), ("a", "b&c")]),
            "scope=openid%20patient%2FPatient.read&a=b%26c"
        );
    }
}
