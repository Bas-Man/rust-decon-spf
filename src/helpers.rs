use crate::mechanism::Kind;
use crate::mechanism::Mechanism;
use crate::mechanism::Qualifier;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use regex::Regex;
use std::num::ParseIntError;

// Provide domain host validation check.
#[cfg(any(feature = "warn-dns", feature = "strict-dns"))]
use addr::parse_dns_name;

/// This is the maximnum number of characters that an Spf Record can store.
pub(crate) const MAX_SPF_STRING_LENGTH: usize = 255;

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
    r"(?i)^(?P<qualifier>[+?~-])?exists:(?:$|)(?P<mechanism>\w.*)";
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
                qualifier_result = char_to_qualifier(qualifier_char);
            }
            //if caps.name("mechanism").is_some() {
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
                        new_mechanism.push('/');
                        new_mechanism.push_str(mechanism_string.as_str());
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

pub(crate) fn spf_check_whitespace(s: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"\s{2,}").unwrap();
        static ref ENDING_SPACE: Regex = Regex::new(r"\s$").unwrap();
    }
    RE.is_match(s) || ENDING_SPACE.is_match(s)
}

pub(crate) fn char_to_qualifier(c: char) -> Qualifier {
    match c {
        '+' => Qualifier::Pass,
        '-' => Qualifier::Fail,
        '~' => Qualifier::SoftFail,
        '?' => Qualifier::Neutral,
        _ => Qualifier::Pass,
    }
}

// builds a string representation of of the mechanisms stored in the Vec<Mechanism<String>>
pub(crate) fn build_spf_str(str: &[Mechanism<String>]) -> String {
    let mut partial_spf = String::new();
    for i in str.iter() {
        partial_spf.push(' ');
        partial_spf.push_str(i.to_string().as_str());
    }
    partial_spf
}
// builds a string representation of of the mechanisms stored in the Vec<Mechanism<IpNetwork>>
pub(crate) fn build_spf_str_from_ip(str: &[Mechanism<IpNetwork>]) -> String {
    let mut partial_spf = String::new();
    for i in str.iter() {
        partial_spf.push(' ');
        partial_spf.push_str(i.to_string().as_str());
    }
    partial_spf
}

#[doc(hidden)]
// Check if the initial character in the string `record` matches `c`
// If they do no match then return the initial character
// if c matches first character of record, we can `+`, a blank modifier equates to `+`
pub(crate) fn return_and_remove_qualifier(record: &str, c: char) -> (Qualifier, &str) {
    // Returns a tuple of (qualifier, &str)
    // &str will have had the qualifier character removed if it existed. The &str will be unchanged
    // if the qualifier was not present
    if c != record.chars().next().unwrap() {
        // qualifier exists. return tuple of qualifier and `record` with qualifier removed.
        (
            char_to_qualifier(record.chars().next().unwrap()),
            remove_qualifier(record),
        )
    } else {
        // qualifier does not exist, default to `+` and return unmodified `record`
        (Qualifier::Pass, record)
    }
}
#[cfg(any(feature = "warn-dns", feature = "strict-dns"))]
pub(crate) fn get_domain_before_slash(s: &str) -> &str {
    if !s.starts_with('/') && s.contains('/') {
        s.split('/').next().unwrap()
    } else {
        s
    }
}
#[test]
#[cfg(feature = "warn-dns")]
fn start_with_slash() {
    let input = "/24";
    assert_eq!(get_domain_before_slash(input), "/24");
}
#[test]
#[cfg(feature = "warn-dns")]
fn domain_contains_slash() {
    let input = "test.com/24";
    assert_eq!(get_domain_before_slash(input), "test.com");
}
#[test]
#[cfg(feature = "warn-dns")]
fn domain_without_slash() {
    let input = "test.com";
    assert_eq!(get_domain_before_slash(input), "test.com");
}

#[cfg(feature = "warn-dns")]
pub(crate) fn check_for_dns_warning(warning_vec: &mut Vec<String>, name: &str) {
    if !dns_is_valid(name) {
        warning_vec.push(name.to_string());
    }
}
// Return true if the domain/host is valid.
#[allow(dead_code)]
#[cfg(any(feature = "warn-dns", feature = "strict-dns"))]
pub(crate) fn dns_is_valid(name: &str) -> bool {
    // These can not be and do not need to be tested. They are always valid.
    if name == "a" || name == "mx" || name == "ptr" || name == "all" || name.starts_with('/') {
        true
    } else {
        match parse_dns_name(name) {
            Err(_) => false,
            Ok(dns) => dns.has_known_suffix(),
        }
    }
}
#[cfg(feature = "warn-dns")]
#[test]
fn invalid_tld() {
    assert_eq!(dns_is_valid("t.xx"), false);
}
#[cfg(feature = "warn-dns")]
#[test]
fn valid_domain() {
    assert_eq!(dns_is_valid("test.com"), true);
}
#[cfg(feature = "warn-dns")]
#[test]
fn valid_a() {
    assert_eq!(dns_is_valid("a"), true);
}
#[cfg(feature = "warn-dns")]
#[test]
fn valid_mx() {
    assert_eq!(dns_is_valid("mx"), true);
}
#[cfg(feature = "warn-dns")]
#[test]
fn valid_ptr() {
    assert_eq!(dns_is_valid("ptr"), true);
}

#[test]
fn return_and_remove_qualifier_no_qualifier() {
    let source = "no prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Pass, c);
    assert_eq!(source, new_str);
}
#[test]
fn return_and_remove_qualifier_pass() {
    let source = "+prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Pass, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_fail() {
    let source = "-prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Fail, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_softfail() {
    let source = "~prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::SoftFail, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_neutral() {
    let source = "?prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Neutral, c);
    assert_eq!("prefix", new_str);
}
#[doc(hidden)]
pub(crate) fn remove_qualifier(record: &str) -> &str {
    // Remove leading (+,-,~,?) character and return an updated str
    let mut chars = record.chars();
    chars.next();
    chars.as_str()
}
#[test]
fn test_remove_qualifier() {
    let test_str = "abc";
    let result = remove_qualifier(test_str);
    assert_eq!(result, "bc");
}
