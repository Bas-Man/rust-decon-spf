//! Defines the supported SPF *Mechanisms* and *Modifiers*  
//!
//! Whilst *Mechanisms* and *Modifiers* differ slightly. This difference is so
//! small as to not require any distinction in the current code base.
//!
//!
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Defines the possible mechanisms.
#[derive(Default, Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Kind {
    /// Represents a *Modifier* of type redirect=  
    /// If this is present, the *All* mechanism should not be present.  
    Redirect,
    /// Represents a Mechanism of type *A*
    /// # Possible Values:  
    /// ```text
    /// a   
    /// a/24  
    /// a:example.com  
    /// a:example.com/24  
    /// ```
    #[default]
    A,
    /// Represents a Mechanism of type *MX*  
    /// Possible values follow the same layout as for [`A`](Kind::A)
    MX,
    /// Represents a Mechanism of type *Include*  
    /// ```test
    /// include:<domain>
    ///```
    Include,
    /// Represents a Mechanism of type *ip4*  
    /// # Example Values:  
    /// ```text
    /// ip4:192.168.11.0/24  
    /// ip4:10.10.1.1
    /// ```
    IpV4,
    /// Represents a Mechanism of type *ip6*
    IpV6,
    /// Represents a Mechanism of type *ptr*
    /// # Note:
    /// This is rarely use.
    /// ```text
    /// ptr
    /// ptr:<domain>
    /// ```
    Ptr,
    /// Represents a Mechanism of type *exists*  
    Exists,
    /// Represents a Mechanism of type *All*
    All,
}

impl Kind {
    /// Returns `true` if the mechanism is [`Redirect`](Kind::Redirect).
    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
    /// Returns `true` if the mechanism is [`A`](Kind::A).
    pub fn is_a(&self) -> bool {
        matches!(self, Self::A)
    }
    /// Returns `true` if the mechanism is [`MX`](Kind::MX).
    pub fn is_mx(&self) -> bool {
        matches!(self, Self::MX)
    }
    /// Returns `true` if the mechanism is [`Include`](Kind::Include).
    pub fn is_include(&self) -> bool {
        matches!(self, Self::Include)
    }
    /// Returns `true` if it is of any ip. V4 or V6
    ///
    /// # Examples:
    ///
    /// ```
    /// # use decon_spf::mechanism::Kind;
    /// let ip4 = Kind::IpV4;
    /// let ip6 = Kind::IpV6;
    /// assert_eq!(ip4.is_ip_v4(), true);
    /// assert_eq!(ip4.is_ip_v6(), false);
    /// assert_eq!(ip4.is_ip(), true);
    /// assert_eq!(ip6.is_ip_v6(), true);
    /// assert_eq!(ip6.is_ip_v4(), false);
    /// assert_eq!(ip6.is_ip(), true);
    /// ```
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::IpV4) || matches!(self, Self::IpV6)
    }
    /// Returns `true` if the mechanism is [`IpV4`](Kind::IpV4).
    pub fn is_ip_v4(&self) -> bool {
        matches!(self, Self::IpV4)
    }
    /// Returns `true` if the mechanism is [`IpV6`](Kind::IpV6).
    pub fn is_ip_v6(&self) -> bool {
        matches!(self, Self::IpV6)
    }
    /// Returns `true` if the mechanism is [`Ptr`](Kind::Ptr).
    pub fn is_ptr(&self) -> bool {
        matches!(self, Self::Ptr)
    }
    /// Returns `true` if the mechanism is [`Exists`](Kind::Exists).
    pub fn is_exists(&self) -> bool {
        matches!(self, Self::Exists)
    }
    /// Returns `true` if the mechanism is [`All`](Kind::All).
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
    /// Returns a reference to the str for kind enums.
    ///
    /// # Examples:
    ///
    /// ```rust
    /// # use decon_spf::mechanism::Kind;
    /// let a = Kind::A;
    /// let mx = Kind::MX;
    /// assert_eq!(a.as_str(), "a");
    /// assert_eq!(a.is_a(), true);
    /// assert_eq!(mx.as_str(), "mx");
    /// assert_eq!(mx.is_mx(), true);
    /// ```
    ///
    pub fn as_str(&self) -> &str {
        match self {
            Kind::Redirect => "redirect=",
            Kind::Include => "include:",
            Kind::A => "a",
            Kind::MX => "mx",
            Kind::IpV4 => "ip4:",
            Kind::IpV6 => "ip6:",
            Kind::Ptr => "ptr",
            Kind::Exists => "exists:",
            Kind::All => "all",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Redirect => write!(f, "redirect="),
            Kind::Include => write!(f, "include:"),
            Kind::A => write!(f, "a"),
            Kind::MX => write!(f, "mx"),
            Kind::IpV4 => write!(f, "ip4:"),
            Kind::IpV6 => write!(f, "ip6:"),
            Kind::Ptr => write!(f, "ptr"),
            Kind::Exists => write!(f, "exists:"),
            Kind::All => write!(f, "all"),
        }
    }
}

#[test]
fn a() {
    let a = Kind::A;
    assert_eq!(a.to_string(), "a");
}
#[test]
fn mx() {
    let a = Kind::MX;
    assert_eq!(a.to_string(), "mx");
}
#[test]
fn redirect() {
    let a = Kind::Redirect;
    assert_eq!(a.to_string(), "redirect=");
}
#[test]
fn include() {
    let a = Kind::Include;
    assert_eq!(a.to_string(), "include:");
}
#[test]
fn ip4() {
    let a = Kind::IpV4;
    assert_eq!(a.to_string(), "ip4:");
}
#[test]
fn ip6() {
    let a = Kind::IpV6;
    assert_eq!(a.to_string(), "ip6:");
}
#[test]
fn ptr() {
    let a = Kind::Ptr;
    assert_eq!(a.to_string(), "ptr");
}
#[test]
fn exists() {
    let a = Kind::Exists;
    assert_eq!(a.to_string(), "exists:");
}
#[test]
fn all() {
    let a = Kind::All;
    assert_eq!(a.to_string(), "all");
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_tests {
    use crate::spf::mechanism::Kind;
    use serde_json;

    #[test]
    fn default() {
        let a = Kind::default();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"A\"");
        let deserialized: Kind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, a);
    }

    #[test]
    fn redirect() {
        let redirect = Kind::Redirect;
        let json = serde_json::to_string(&redirect).unwrap();
        assert_eq!(json, "\"Redirect\"");
        let deserialized: Kind = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, redirect);
    }
}
