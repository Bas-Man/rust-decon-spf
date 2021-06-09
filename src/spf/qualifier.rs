/// An enumeration of possible qualifiers that are used in SPF records.

#[derive(Debug, Clone, PartialEq)]
pub enum Qualifier {
    /// This is the default value for a qualifier if the value is not present in the SPF record.
    /// It is denoted by '+' (Plus Sign)
    Pass,
    /// It is denoted by '-' (Minus Sign)
    Fail,
    /// It is denoted by '~' (Tidle Mark)
    SoftFail,
    /// It is denoted by '?' (Question Mark)
    Neutral,
}

impl Default for Qualifier {
    fn default() -> Self {
        Self::Pass
    }
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
    /// Returns the character, as a string slice, that represents a given ['Qualifier'](Qualifier) value in
    /// SPF.
    pub fn as_str(&self) -> &str {
        match self {
            Qualifier::Pass => return "",
            Qualifier::Fail => return "-",
            Qualifier::SoftFail => return "~",
            Qualifier::Neutral => return "?",
        }
    }
    /// Returns the character, as a `char`, that represents a given ['Qualifier'](Qualifier) value in
    /// SPF.
    pub fn as_char(&self) -> char {
        match self {
            Qualifier::Pass => return '+',
            Qualifier::Fail => return '-',
            Qualifier::SoftFail => return '~',
            Qualifier::Neutral => return '?',
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
