use crate::mechanism::Mechanism;
use crate::mechanism::MechanismKind;
use crate::mechanism::Qualifier;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use regex::Regex;

// List of Regular Expressions used to parse Spf Mechanisms.
pub(crate) const MECHANISM_A_PATTERN: &str =
    r"^(?P<qualifier>[+?~-])?a[:]{0,1}(?P<mechanism>[/]{0,1}.+)?";
pub(crate) const MECHANISM_MX_PATTERN: &str =
    r"^(?P<qualifier>[+?~-])?mx[:]{0,1}(?P<mechanism>[/]{0,1}.+)?";
pub(crate) const MECHANISM_PTR_PATTERN: &str =
    r"^(?P<qualifier>[+?~-])?ptr[:]{0,1}(?P<mechanism>.+)?";
pub(crate) const MECHANISM_EXISTS_PATTERN: &str =
    r"^(?P<qualifier>[+?~-])?exists[:]{0,1}(?P<mechanism>.+)?";

// Create a new mechanism for a matched regular expression.
pub(crate) fn capture_matches(string: &str, kind: MechanismKind) -> Option<Mechanism<String>> {
    lazy_static! {
        static ref A_RE: Regex = Regex::new(MECHANISM_A_PATTERN).unwrap();
        static ref MX_RE: Regex = Regex::new(MECHANISM_MX_PATTERN).unwrap();
        static ref PTR_RE: Regex = Regex::new(MECHANISM_PTR_PATTERN).unwrap();
        static ref EXISTS_RE: Regex = Regex::new(MECHANISM_EXISTS_PATTERN).unwrap();
    }
    let caps = match kind {
        MechanismKind::A => A_RE.captures(string),
        MechanismKind::MX => MX_RE.captures(string),
        MechanismKind::Ptr => PTR_RE.captures(string),
        MechanismKind::Exists => EXISTS_RE.captures(string),
        _ => unreachable!(),
    };
    let qualifier_char: char;
    let mut qualifier_result: Qualifier = Qualifier::Pass;
    let mechanism_string: String;
    let mechanism;
    match caps {
        None => return None,
        Some(caps) => {
            // There was a match
            if caps.name("qualifier").is_some() {
                qualifier_char = caps
                    .name("qualifier")
                    .unwrap()
                    .as_str()
                    .chars()
                    .nth(0)
                    .unwrap();
                qualifier_result = char_to_qualifier(qualifier_char);
            };
            if caps.name("mechanism").is_some() {
                mechanism_string = caps.name("mechanism").unwrap().as_str().to_string();
                mechanism = Mechanism::new(
                    kind,
                    qualifier_result,
                    Some((*mechanism_string).to_string()),
                );
            } else {
                mechanism = Mechanism::new(kind, qualifier_result, None);
            }

            Some(mechanism)
        }
    }
}

pub(crate) fn char_to_qualifier(c: char) -> Qualifier {
    match c {
        '+' => return Qualifier::Pass,
        '-' => return Qualifier::Fail,
        '~' => return Qualifier::SoftFail,
        '?' => return Qualifier::Neutral,
        _ => return Qualifier::Pass,
    }
}

// builds a string representation of of the mechanisms stored in the Vec<Mechanism<String>>
pub(crate) fn build_spf_str(str: Option<&Vec<Mechanism<String>>>) -> String {
    let mut partial_spf = String::new();
    for i in str.unwrap().iter() {
        partial_spf.push_str(" ");
        partial_spf.push_str(i.to_string().as_str());
    }
    partial_spf
}
// builds a string representation of of the mechanisms stored in the Vec<Mechanism<IpNetwork>>
pub(crate) fn build_spf_str_from_ip(str: Option<&Vec<Mechanism<IpNetwork>>>) -> String {
    let mut partial_spf = String::new();
    for i in str.unwrap().iter() {
        partial_spf.push_str(" ");
        partial_spf.push_str(i.to_string().as_str());
    }
    partial_spf
}
