use lazy_static::lazy_static;
use regex::Regex;
use std::num::ParseIntError;
use crate::mechanism::{Kind, Mechanism, Qualifier};

// List of Regular Expressions used to parse Spf Mechanisms.
// Note: This Regex has errors. Needs to be reworked.
// Tends to match any string starting with 'a'
pub(crate) const MECHANISM_A_PATTERN: &str =
    r"(?i)^(?P<qualifier>[+?~-])?a(?:$|[^a-z.])(?P<mechanism>[a-z0-9].*|\d{1,3})?$";
pub(crate) const MECHANISM_MX_PATTERN: &str =
    r"(?i)^(?P<qualifier>[+?~-])?mx(?:$|[^a-z.])(?P<mechanism>[a-z0-9].*|\d{1,3})?$";
pub(crate) const MECHANISM_PTR_PATTERN: &str = r"(?i)^(?P<qualifier>[+?~-])?ptr(?:$|[^a-z./])(?P<mechanism>(?:[[:word:]]+\.)*[[:word:]]+
?)?$";
pub(crate) const MECHANISM_EXISTS_PATTERN: &str =
    r"(?i)^(?P<qualifier>[+?~-])?exists:(?P<mechanism>(?:%|\w).*)";
// All Regex is currently not being used.
pub(crate) const MECHANISM_ALL_PATTERN: &str = r"^(?P<qualifier>[+?~-])?all(?P<mechanism>\s)?$";

// Create a new mechanism for a matched regular expression.
pub(crate) fn capture_matches(string: &str, kind: Kind) -> Option<Mechanism<String>> {
    lazy_static! {
        static ref A_RE: Regex = Regex::new(MECHANISM_A_PATTERN).unwrap();
        static ref MX_RE: Regex = Regex::new(MECHANISM_MX_PATTERN).unwrap();
        static ref PTR_RE: Regex = Regex::new(MECHANISM_PTR_PATTERN).unwrap();
        static ref EXISTS_RE: Regex = Regex::new(MECHANISM_EXISTS_PATTERN).unwrap();
        static ref ALL_RE: Regex = Regex::new(MECHANISM_ALL_PATTERN).unwrap();
    }
    let caps = match kind {
        Kind::A => A_RE.captures(string),
        Kind::MX => MX_RE.captures(string),
        Kind::Ptr => PTR_RE.captures(string),
        Kind::Exists => EXISTS_RE.captures(string),
        _ => unreachable!(),
    };
    let qualifier_char: char;
    let mut qualifier_result: Qualifier = Qualifier::Pass;
    let mut mechanism_string: String;
    let mechanism;
    match caps {
        None => None,
        Some(caps) => {
            // There was a match
            if let Some(qualifier) = caps.name("qualifier") {
                qualifier_char = qualifier.as_str().chars().next().unwrap();
                qualifier_result = crate::core::char_to_qualifier(qualifier_char);
            }
            if let Some(mechanism_value) = caps.name("mechanism") {
                let mut new_mechanism: String = String::new();
                mechanism_string = mechanism_value.as_str().to_string();
                // Check if we got a match on a number. No more than 3 digits.
                // Regex matches [ domain, domain/num, num] so we handle the "num" case here
                if mechanism_string.len() < 4 {
                    let num: Result<i32, ParseIntError> = mechanism_string.parse();
                    // Check that we can convert this to an integer. If we can. Its ok.
                    // convert mechanism_string from "num" to "/num"
                    if num.is_ok() {
                        new_mechanism.push_str(&format!("/{}", mechanism_string.as_str()));
                    } else {
                        // Did not match a number. Probably [a-z]. This makes it invalid.
                        return None;
                    }
                }
                if !new_mechanism.is_empty() {
                    mechanism_string = new_mechanism;
                }
                mechanism = Mechanism::generic_inclusive(
                    kind,
                    qualifier_result,
                    Some((*mechanism_string).to_string()),
                );
            } else {
                mechanism = Mechanism::generic_inclusive(kind, qualifier_result, None);
            }
            Some(mechanism)
        }
    }
}
