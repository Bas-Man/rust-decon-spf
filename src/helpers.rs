use crate::mechanism::Kind;
use crate::mechanism::Mechanism;
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
pub(crate) fn capture_matches(string: &str, kind: Kind) -> Option<Mechanism<String>> {
    lazy_static! {
        static ref A_RE: Regex = Regex::new(MECHANISM_A_PATTERN).unwrap();
        static ref MX_RE: Regex = Regex::new(MECHANISM_MX_PATTERN).unwrap();
        static ref PTR_RE: Regex = Regex::new(MECHANISM_PTR_PATTERN).unwrap();
        static ref EXISTS_RE: Regex = Regex::new(MECHANISM_EXISTS_PATTERN).unwrap();
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

pub(crate) fn spf_has_consecutive_whitespace(spf: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"\s{2,}").unwrap();
    }
    RE.is_match(spf)
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

#[doc(hidden)]
// Check if the initial character in the string `record` matches `c`
// If they do no match then return the initial character
// if c matches first character of record, we can `+`, a blank modiifer equates to `+`
pub(crate) fn return_and_remove_qualifier(record: &str, c: char) -> (Qualifier, &str) {
    // Returns a tuple of (qualifier, &str)
    // &str will have had the qualifier character removed if it existed. The &str will be unchanged
    // if the qualifier was not present
    if c != record.chars().nth(0).unwrap() {
        // qualifier exists. return tuple of qualifier and `record` with qualifier removed.
        (
            char_to_qualifier(record.chars().nth(0).unwrap()),
            remove_qualifier(record),
        )
    } else {
        // qualifier does not exist, default to `+` and return unmodified `record`
        (Qualifier::Pass, record)
    }
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
