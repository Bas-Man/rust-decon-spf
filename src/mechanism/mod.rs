//! This module contains the tools and functions to dealing with Mechanisms found within an Spf DNS record.  
//!
mod errors;
mod kind;
mod parsedmechanism;
mod qualifier;
mod tests;

pub use crate::mechanism::errors::MechanismError;
pub use crate::mechanism::kind::Kind;
pub use crate::mechanism::parsedmechanism::ParsedMechanism;
pub use crate::mechanism::qualifier::Qualifier;

use crate::helpers;
use ipnetwork::IpNetwork;
use std::{convert::TryFrom, str::FromStr};

// //! A struct created either by having an existing SPF record `parsed` or programmatically created.

/// Stores its `Kind`, `Qualifier` and its `Value`
#[derive(Debug, Clone)]
pub struct Mechanism<T> {
    kind: Kind,
    qualifier: Qualifier,
    rrdata: Option<T>,
}

/// Create a Mechanism<String> from the provided string.
///
/// # Examples:
///```rust
/// use decon_spf::mechanism::Mechanism;
/// let a: Mechanism<String> = "a".parse().unwrap();
/// assert_eq!(a.kind().is_a(), true);
///
/// let mx = "mx".parse::<Mechanism<String>>().unwrap();
/// assert_eq!(mx.kind().is_mx(), true);
/// let mx2 = "-mx:example.com".parse::<Mechanism<String>>().unwrap();
/// assert_eq!(mx2.qualifier().is_fail(), true);
/// assert_eq!(mx2.to_string(), "-mx:example.com");
///
///```
impl FromStr for Mechanism<String> {
    type Err = MechanismError;

    fn from_str(s: &str) -> Result<Mechanism<String>, Self::Err> {
        // A String ending wiith either ':' or "/" is always invalid.
        if s.ends_with(':') || s.ends_with('/') {
            return Err(MechanismError::NotValidMechanismFormat(s.to_string()));
        };
        if s.contains("ip4:") || s.contains("ip6:") {
            return Err(MechanismError::NotValidMechanismFormat(s.to_string()));
        }
        if s.contains("redirect=") {
            let items = s.rsplit('=');
            for item in items {
                return Ok(Mechanism::new(
                    Kind::Redirect,
                    Qualifier::Pass,
                    Some(item.to_string()),
                ));
            }
        } else if s.contains("include:") {
            let qualifier_and_modified_str = helpers::return_and_remove_qualifier(s, 'i');
            for item in s.rsplit(':') {
                return Ok(Mechanism::new_include(
                    qualifier_and_modified_str.0,
                    item.to_string(),
                ));
            }
        } else if s.ends_with("all") && (s.len() == 3 || s.len() == 4) {
            return Ok(Mechanism::new_all(
                helpers::return_and_remove_qualifier(s, 'a').0,
            ));
        } else if let Some(a_mechanism) = helpers::capture_matches(s, Kind::A) {
            return Ok(a_mechanism);
        } else if let Some(mx_mechanism) = helpers::capture_matches(s, Kind::MX) {
            return Ok(mx_mechanism);
        } else if let Some(ptr_mechanism) = helpers::capture_matches(s, Kind::Ptr) {
            return Ok(ptr_mechanism);
        } else if let Some(exists_mechanism) = helpers::capture_matches(s, Kind::Exists) {
            if !exists_mechanism.raw().contains('/') {
                return Ok(exists_mechanism);
            }
        }
        Err(MechanismError::NotValidMechanismFormat(s.to_string()))
    }
}

impl TryFrom<&str> for Mechanism<String> {
    type Error = MechanismError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Mechanism::from_str(s)
    }
}

/// Create a Mechanism<IpNetwork> from the provided string.
///
/// # Examples:
///```rust
/// use decon_spf::mechanism::MechanismError;
/// use decon_spf::mechanism::Mechanism;
/// # use ipnetwork::IpNetwork;
/// let ip4: Mechanism<IpNetwork> = "ip4:203.32.160.0/24".parse().unwrap();
/// assert_eq!(ip4.kind().is_ip_v4(), true);
///
/// let ip6 = "ip6:2001:4860:4000::/36".parse::<Mechanism<IpNetwork>>().unwrap();
/// assert_eq!(ip6.kind().is_ip_v6(), true);
///
/// let bad_ip4: Result<Mechanism<IpNetwork>, MechanismError> = "ip4:203.32.160.0/33".parse();
/// assert_eq!(bad_ip4.unwrap_err().to_string(), "invalid address: 203.32.160.0/33.");
///
/// let ip6_but_ip6: Result<Mechanism<IpNetwork>, MechanismError> = "ip6:203.32.160.0/24".parse();
/// let err = ip6_but_ip6.unwrap_err();
/// assert_eq!(err, MechanismError::NotIP6Network("203.32.160.0/24".to_string()));
/// assert_eq!(err.to_string(), "Was given ip6:203.32.160.0/24. This is not an ip6 network.");
///```
impl FromStr for Mechanism<IpNetwork> {
    type Err = MechanismError;

    fn from_str(s: &str) -> Result<Mechanism<IpNetwork>, Self::Err> {
        if s.contains("ip4:") || s.contains("ip6:") {
            let mut kind = Kind::IpV4;
            let mut raw_ip: Option<&str> = None;
            let qualifier_and_modified_str = helpers::return_and_remove_qualifier(s, 'i');
            if qualifier_and_modified_str.1.contains("ip4") {
                kind = Kind::IpV4;
                raw_ip = qualifier_and_modified_str.1.strip_prefix("ip4:");
            } else if qualifier_and_modified_str.1.contains("ip6") {
                kind = Kind::IpV6;
                raw_ip = qualifier_and_modified_str.1.strip_prefix("ip6:")
            };
            let parsed = raw_ip.unwrap().parse();
            if parsed.is_ok() {
                let ip: IpNetwork = parsed.unwrap();
                if ip.is_ipv4() && kind.is_ip_v4() {
                    return Ok(Mechanism::new_ip4(qualifier_and_modified_str.0, ip));
                } else if ip.is_ipv4() && !kind.is_ip_v4() {
                    return Err(MechanismError::NotIP6Network(ip.to_string()));
                } else if ip.is_ipv6() && kind.is_ip_v6() {
                    return Ok(Mechanism::new_ip6(qualifier_and_modified_str.0, ip));
                } else if ip.is_ipv6() && !kind.is_ip_v6() {
                    return Err(MechanismError::NotIP4Network(ip.to_string()));
                };
            } else {
                return Err(MechanismError::NotValidIPNetwork(
                    parsed.unwrap_err().to_string(),
                ));
            };
        }
        // Catch all. This is not an ip4 or ip6 spf string.
        Err(MechanismError::NotValidMechanismFormat(s.to_string()))
    }
}

impl TryFrom<&str> for Mechanism<IpNetwork> {
    type Error = MechanismError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Mechanism::from_str(s)
    }
}

impl<T> Mechanism<T> {
    //! These are the generic methods for the struct of Mechanism.  
    //! All the following methods can be used on any struct of type Mechanism.
    #[doc(hidden)]
    pub fn new(kind: Kind, qualifier: Qualifier, mechanism: Option<T>) -> Self {
        Self {
            kind,
            qualifier,
            rrdata: mechanism,
        }
    }
    /// check mechanism is pass
    pub fn is_pass(&self) -> bool {
        self.qualifier == Qualifier::Pass
    }
    /// check mechanism is fail
    pub fn is_fail(&self) -> bool {
        self.qualifier == Qualifier::Fail
    }
    /// check mechanism is softfail
    pub fn is_softfail(&self) -> bool {
        self.qualifier == Qualifier::SoftFail
    }
    /// check mechanism is neutral
    pub fn is_neutral(&self) -> bool {
        self.qualifier == Qualifier::Neutral
    }
    /// Returns a reference to the Mechanism's Kind
    pub fn kind(&self) -> &Kind {
        &self.kind
    }
    /// Returns a reference to the Mechanism's Qualifier
    pub fn qualifier(&self) -> &Qualifier {
        &self.qualifier
    }
    /// Returns a reference to the Mechanism's Value.
    /// This could return a `String`, `IpNetwork`, or `None`
    pub fn mechanism(&self) -> &Option<T> {
        &self.rrdata
    }
}

impl Mechanism<String> {
    /// Create a new Mechanism struct of `Redirect`
    #[doc(hidden)]
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Redirect, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `A` with no string value.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_a = Mechanism::new_a_without_mechanism(Qualifier::Pass);
    /// assert_eq!(mechanism_a.kind().is_a(), true);
    /// assert_eq!(mechanism_a.raw(), "a".to_string());
    /// assert_eq!(mechanism_a.mechanism().is_none(), true);
    #[doc(hidden)]
    pub fn new_a_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::A, qualifier, None)
    }

    /// Create a new Mechanism struct of `A` with string value.
    ///
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_of_a = Mechanism::new_a_with_mechanism(Qualifier::Pass,
    ///                                                      String::from("example.com"));
    /// assert_eq!(mechanism_of_a.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_a.raw(), "example.com");
    /// assert_eq!(mechanism_of_a.to_string(), "a:example.com");
    /// ```
    #[doc(hidden)]
    pub fn new_a_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::A, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `MX` without string value.
    ///
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_mx = Mechanism::new_mx_without_mechanism(Qualifier::Pass);
    /// assert_eq!(mechanism_mx.kind().is_mx(), true);
    /// assert_eq!(mechanism_mx.raw(), "mx");
    /// ```
    #[doc(hidden)]
    pub fn new_mx_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::MX, qualifier, None)
    }

    /// Create a new Mechanism struct of `MX`
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_mx = Mechanism::new_mx_with_mechanism(Qualifier::Pass,
    ///                                                     String::from("example.com"));
    /// assert_eq!(mechanism_mx.raw(), "example.com");
    /// assert_eq!(mechanism_mx.to_string(), "mx:example.com")
    /// ```
    #[doc(hidden)]
    pub fn new_mx_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::MX, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Include`
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_of_include = Mechanism::new_include(Qualifier::Pass,
    ///                                                   String::from("example.com"));
    /// assert_eq!(mechanism_of_include.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_include.raw(), "example.com");
    /// assert_eq!(mechanism_of_include.to_string(), "include:example.com");
    /// let mechanism_of_include2 = Mechanism::new_include(Qualifier::SoftFail,
    ///                                                    String::from("example.com"));
    /// assert_eq!(mechanism_of_include2.to_string(), "~include:example.com")
    /// ```
    #[doc(hidden)]
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Include, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Ptr` with no value
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_of_ptr = Mechanism::new_ptr_without_mechanism(Qualifier::Fail);
    /// assert_eq!(mechanism_of_ptr.to_string(), "-ptr");
    #[doc(hidden)]
    pub fn new_ptr_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::Ptr, qualifier, None)
    }

    /// Create a new Mechanism struct of `Ptr`
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_of_ptr = Mechanism::new_ptr_with_mechanism(Qualifier::Pass,
    ///                                                          String::from("example.com"));
    /// assert_eq!(mechanism_of_ptr.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_ptr.raw(), "example.com");
    /// assert_eq!(mechanism_of_ptr.to_string(), "ptr:example.com");
    #[doc(hidden)]
    pub fn new_ptr_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Ptr, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Exists`
    #[doc(hidden)]
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Exists, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `All`
    #[doc(hidden)]
    pub fn new_all(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::All, qualifier, None)
    }

    /// Return the mechanism string stored in the `Mechanism`
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_a = Mechanism::new_a_without_mechanism(Qualifier::Neutral);
    /// assert_eq!(mechanism_a.raw(), "a");
    /// let mechanism_a_string = Mechanism::new_a_with_mechanism(Qualifier::Neutral,
    ///                                                          String::from("example.com"));
    /// assert_eq!(mechanism_a_string.raw(), "example.com");
    pub fn raw(&self) -> String {
        if self.rrdata.is_none() {
            self.kind().to_string()
        } else {
            self.rrdata.as_ref().unwrap().to_string()
        }
    }

    /// Rebuild and return the string representation of the given mechanism
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let mechanism_a = Mechanism::new_a_without_mechanism(Qualifier::Neutral);
    /// assert_eq!(mechanism_a.to_string(), "?a");
    /// let mechanism_a_string = Mechanism::new_a_with_mechanism(Qualifier::Pass,
    ///                                                          String::from("example.com"));
    /// assert_eq!(mechanism_a_string.to_string(), "a:example.com");
    #[deprecated(
        since = "0.2.0",
        note = "This will be removed in a future release. Use to_string() which is implemented through Display trait."
    )]
    pub fn string(&self) -> String {
        self.build_string()
    }
    fn build_string(&self) -> String {
        let mut mechanism_str = String::new();
        let tmp_mechanism_str;
        if self.qualifier != Qualifier::Pass {
            mechanism_str.push_str(self.qualifier.as_str());
        };
        mechanism_str.push_str(self.kind().as_str());
        if self.rrdata.is_some() {
            tmp_mechanism_str = self.rrdata.as_ref().unwrap().as_str();
        } else {
            tmp_mechanism_str = ""
        }
        match self.kind {
            Kind::A | Kind::MX => {
                // This must be starting with 'domain.com' So prepend ':'
                if !tmp_mechanism_str.starts_with('/') && !tmp_mechanism_str.is_empty() {
                    mechanism_str.push(':')
                }
            }
            Kind::Ptr => {
                // This Ptr has a domain. Prepend ':'
                if !tmp_mechanism_str.is_empty() {
                    mechanism_str.push(':')
                }
            }
            // Do nothing in all other cases.
            _ => {}
        }
        mechanism_str.push_str(tmp_mechanism_str);
        mechanism_str
    }
}

impl std::fmt::Display for Mechanism<String> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_string())
    }
}

impl Mechanism<IpNetwork> {
    /// Create a new V4 or V6 Mechanism<IpNetwork>  
    /// Will correctly set its `kind` based on the `IpNetwork` type.
    ///
    /// # Examples:
    /// ```
    /// # use ipnetwork::IpNetwork;
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    ///
    /// // Requires: use ipnetwork::IpNetwork;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let mechanism = Mechanism::new_ip(Qualifier::Pass, ip);
    /// assert_eq!(mechanism.kind().is_ip_v4(), true);
    /// assert_eq!(mechanism.raw(), "192.168.11.0/24".to_string());
    /// assert_eq!(mechanism.as_network().to_string(), "192.168.11.0/24".to_string());
    /// assert_eq!(mechanism.as_network().prefix(), 24);
    ///
    /// // This section does not require use of ipnetwork::IpNetwork;
    /// let mechanism_ip4 = Mechanism::new_ip(Qualifier::Pass,
    ///                                       "203.32.160.0/23".parse().unwrap());
    /// assert_eq!(mechanism_ip4.kind().is_ip(), true);
    /// assert_eq!(mechanism_ip4.to_string(), "ip4:203.32.160.0/23".to_string());
    /// let mechanism_ip6 = Mechanism::new_ip(Qualifier::Pass,
    ///                                       "2001:4860:4000::/36".parse().unwrap());
    /// assert_eq!(mechanism_ip6.kind().is_ip(), true);
    /// assert_eq!(mechanism_ip6.to_string(), "ip6:2001:4860:4000::/36".to_string());
    ///```
    #[doc(hidden)]
    pub fn new_ip(qualifier: Qualifier, mechanism: IpNetwork) -> Mechanism<IpNetwork> {
        if mechanism.is_ipv4() {
            Mechanism::new_ip4(qualifier, mechanism)
        } else {
            Mechanism::new_ip6(qualifier, mechanism)
        }
    }

    /// Create a new Mechanism<IpNetwork> of IP4
    #[doc(hidden)]
    pub fn new_ip4(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::new(Kind::IpV4, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism<IpNetwork> of IP6
    #[doc(hidden)]
    pub fn new_ip6(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::new(Kind::IpV6, qualifier, Some(mechanism))
    }
    /// Returns the simple string representation of the mechanism
    // # Example
    //
    // ```
    // use ipnetwork::IpNetwork;
    // use decon_spf::mechanism::Qualifier;
    // use decon_spf::mechanism::Mechanism;
    // let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    // let ip_mechanism = Mechanism::new_ip4(Qualifier::Pass, ip);
    // assert_eq!(ip_mechanism.raw(), "192.168.11.0/24");
    // assert_eq!(ip_mechanism.kind().is_ip(), true);
    // ```
    //
    pub fn raw(&self) -> String {
        // Consider striping ':' and "/" if they are the first characters.
        self.rrdata.unwrap().to_string()
    }

    /// Returns the mechanism string representation of an IP4/6 mechanism.
    /// # Example
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = Mechanism::new_ip4(Qualifier::Pass, ip);
    /// assert_eq!(ip_mechanism.to_string(), "ip4:192.168.11.0/24");
    /// assert_eq!(ip_mechanism.as_network(), &ip);
    /// ```
    ///
    #[deprecated(
        since = "0.2.0",
        note = "This will be removed in a future release. Use to_string() which is implemented through Display trait."
    )]
    pub fn string(&self) -> String {
        self.build_string()
    }
    fn build_string(&self) -> String {
        let mut ip_mechanism_str = String::new();
        if self.qualifier != Qualifier::Pass {
            ip_mechanism_str.push_str(self.qualifier.as_str());
        };
        ip_mechanism_str.push_str(self.kind().as_str());
        ip_mechanism_str.push_str(self.rrdata.unwrap().to_string().as_str());
        ip_mechanism_str
    }

    /// Returns the mechanism as an `IpNetwork`
    pub fn as_network(&self) -> &IpNetwork {
        self.rrdata.as_ref().unwrap()
    }
}

impl std::fmt::Display for Mechanism<IpNetwork> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_string())
    }
}
