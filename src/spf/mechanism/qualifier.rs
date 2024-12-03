//! An enumeration of possible qualifiers that are used in Mechanism record.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Declaration for possible `Qualifier` of a given Mechanism
#[derive(Default, Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Qualifier {
    /// This is the default value for a qualifier if the value is not present in the SPF record.
    /// It is denoted by '+' (Plus Sign)
    #[default]
    Pass,
    /// It is denoted by '-' (Minus Sign)
    Fail,
    /// It is denoted by '~' (Tilde Mark)
    SoftFail,
    /// It is denoted by '?' (Question Mark)
    Neutral,
}

impl Qualifier {
    /// Returns `true` if the qualifier is [`Pass`](Qualifier::Pass).
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns `true` if the qualifier is [`Fail`](Qualifier::Fail).
    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail)
    }

    /// Returns `true` if the qualifier is [`SoftFail`](Qualifier::SoftFail).
    pub fn is_softfail(&self) -> bool {
        matches!(self, Self::SoftFail)
    }

    /// Returns `true` if the qualifier is [`Neutral`](Qualifier::Neutral).
    pub fn is_neutral(&self) -> bool {
        matches!(self, Self::Neutral)
    }
    /// Returns the character, as a string slice, that represents a given ['Qualifier'](Qualifier)
    /// value in SPF.
    pub fn as_str(&self) -> &str {
        match self {
            Qualifier::Pass => "",
            Qualifier::Fail => "-",
            Qualifier::SoftFail => "~",
            Qualifier::Neutral => "?",
        }
    }
    /// Returns the character, as a `char`, that represents a given ['Qualifier'](Qualifier)
    /// value in SPF.
    pub fn as_char(&self) -> char {
        match self {
            Qualifier::Pass => '+',
            Qualifier::Fail => '-',
            Qualifier::SoftFail => '~',
            Qualifier::Neutral => '?',
        }
    }
}

impl std::fmt::Display for Qualifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Qualifier::Pass => write!(f, ""),
            Qualifier::Fail => write!(f, "-"),
            Qualifier::SoftFail => write!(f, "~"),
            Qualifier::Neutral => write!(f, "?"),
        }
    }
}
#[test]
fn is_pass() {
    let q = Qualifier::Pass;
    assert_eq!(q.is_pass(), true);
}
#[test]
fn is_fail() {
    let q = Qualifier::Fail;
    assert_eq!(q.is_fail(), true);
}
#[test]
fn is_softfail() {
    let q = Qualifier::SoftFail;
    assert_eq!(q.is_softfail(), true);
}
#[test]
fn is_neutral() {
    let q = Qualifier::Neutral;
    assert_eq!(q.is_neutral(), true);
}
#[test]
fn as_pass() {
    let q = Qualifier::Pass;
    assert_eq!(q.as_str(), "");
}
#[test]
fn as_fail() {
    let q = Qualifier::Fail;
    assert_eq!(q.as_str(), "-");
}
#[test]
fn as_softfail() {
    let q = Qualifier::SoftFail;
    assert_eq!(q.as_str(), "~");
}
#[test]
fn as_neutral() {
    let q = Qualifier::Neutral;
    assert_eq!(q.as_str(), "?");
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_test {
    use crate::spf::mechanism::Qualifier;
    use serde_json;

    #[test]
    fn pass() {
        let q = Qualifier::Pass;
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "\"Pass\"");
        let deserialized: Qualifier = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, q);
    }

    #[test]
    fn fail() {
        let q = Qualifier::Fail;
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "\"Fail\"");
        let deserialized: Qualifier = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, q);
    }
}
