//! Defines the supported SPF Mechanisms  

/// This enum defines the possible mechanisms.
#[derive(Debug, Clone, PartialEq)]
pub enum MechanismKind {
    /// Represents a Mechanism of type redirect=  
    /// If this is present, no other mechanism should be present.  
    Redirect,
    /// Represents a Mechanism of type a
    /// # Possible Values:  
    /// ```bash
    /// a   
    /// a/24  
    /// a:example.com  
    /// a:example.com/24  
    /// ```
    A,
    /// Represents a Mechanism of type mx
    /// Possible values follow the same loyout as for [`A`](MechanismKind::A)
    MX,
    /// Represents a Mechanism of type include:
    /// **Note**: There should only be a maximum of 10 Includes.
    Include,
    /// Represents a Mechanism of type ip4:  
    /// # Example Values:  
    /// ```text
    /// ip4:192.168.11.0/24  
    /// ip4:10.10.1.1
    /// ```
    IpV4,
    /// Represents a Mechanism of type ip6:
    IpV6,
    /// Represents a Mechanism of type ptr: Note: This is rarely use.
    Ptr,
    /// Represents a Mechanism of type exists:
    Exists,
    /// Represents a Mechanism of type all
    All,
}

impl MechanismKind {
    /// Returns `true` if the mechanism is [`Redirect`](MechanismKind::Redirect).
    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
    /// Returns `true` if the mechanism is [`A`](MechanismKind::A).
    pub fn is_a(&self) -> bool {
        matches!(self, Self::A)
    }
    /// Returns `true` if the mechanism is [`MX`](MechanismKind::MX).
    pub fn is_mx(&self) -> bool {
        matches!(self, Self::MX)
    }
    /// Returns `true` if the mechanism is [`Include`](MechanismKind::Include).
    pub fn is_include(&self) -> bool {
        matches!(self, Self::Include)
    }
    /// Returns `true` if the mechanism is [`IpV4`](MechanismKind::IpV4).
    pub fn is_ip_v4(&self) -> bool {
        matches!(self, Self::IpV4)
    }
    /// Returns `true` if the mechanism is [`IpV6`](MechanismKind::IpV6).
    pub fn is_ip_v6(&self) -> bool {
        matches!(self, Self::IpV6)
    }
    /// Returns `true` if the mechanism is [`Ptr`](MechanismKind::Ptr).
    pub fn is_ptr(&self) -> bool {
        matches!(self, Self::Ptr)
    }
    /// Returns `true` if the mechanism is [`Exists`](MechanismKind::Exists).
    pub fn is_exists(&self) -> bool {
        matches!(self, Self::Exists)
    }
    /// Returns `true` if the mechanism is [`All`](MechanismKind::All).
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
    /// Returns a reference to the str for kind enums.
    ///
    /// Examples
    ///
    /// ```rust
    /// # use decon_spf::spf::kinds;
    /// let a = kinds::MechanismKind::A;
    /// let mx = kinds::MechanismKind::MX;
    /// assert_eq!(a.as_str(), "a");
    /// assert_eq!(mx.as_str(), "mx");
    /// ```
    ///
    pub fn as_str(&self) -> &str {
        let push_str = match self {
            MechanismKind::Redirect => "redirect=",
            MechanismKind::Include => "include:",
            MechanismKind::A => "a",
            MechanismKind::MX => "mx",
            MechanismKind::IpV4 => "ip4:",
            MechanismKind::IpV6 => "ip6:",
            MechanismKind::Ptr => "ptr",
            MechanismKind::Exists => "exists:",
            MechanismKind::All => "all",
        };
        push_str
    }
}

impl Default for MechanismKind {
    fn default() -> Self {
        Self::A
    }
}

#[test]
fn test_kind_a() {
    let a = MechanismKind::A;
    assert_eq!(a.as_str(), "a");
}
#[test]
fn test_kind_mx() {
    let a = MechanismKind::MX;
    assert_eq!(a.as_str(), "mx");
}
#[test]
fn test_kind_redirect() {
    let a = MechanismKind::Redirect;
    assert_eq!(a.as_str(), "redirect=");
}
#[test]
fn test_kind_include() {
    let a = MechanismKind::Include;
    assert_eq!(a.as_str(), "include:");
}
#[test]
fn test_kind_ip4() {
    let a = MechanismKind::IpV4;
    assert_eq!(a.as_str(), "ip4:");
}
#[test]
fn test_kind_ip6() {
    let a = MechanismKind::IpV6;
    assert_eq!(a.as_str(), "ip6:");
}
#[test]
fn test_kind_ptr() {
    let a = MechanismKind::Ptr;
    assert_eq!(a.as_str(), "ptr");
}
#[test]
fn test_kind_exists() {
    let a = MechanismKind::Exists;
    assert_eq!(a.as_str(), "exists:");
}
#[test]
fn test_kind_all() {
    let a = MechanismKind::All;
    assert_eq!(a.as_str(), "all");
}
