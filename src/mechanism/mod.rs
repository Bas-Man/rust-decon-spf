//! This module contains the tools and functions to dealing with Mechanisms found within an Spf DNS record.  
//!
//! The Mechanism struct stores information about the `mechanism` or `modifier` found in the string representation
//! of the `Spf` record. It contains a number of methods for transversing and accessing this data.
//!
//! The module also contains a number of ways to create the `Mechanism` instances.
//! - [`ParsedMechanism`](parsedmechanism::ParsedMechanism)
//!     - This provides a unified method for parsing any mechanism string. It will either contain a `Mechanism<String>`
//! or a `Mechanism<IpNetwork>` if the string is succesfully parsed.
//! - Both `Mechanism<String>` and `Mechanism<IpNetwork>` have the `FromStr` trait implemented. Allowing for the strings
//! to be `parsed()`
//! - The `Mechanism` struct also has a number of specfic methods which can be used to create related mechanisms; which are
//! used with the `FromStr` trait.
//!
mod errors;
mod kind;
mod parsedmechanism;
mod qualifier;
#[cfg(test)]
mod tests;

pub use crate::mechanism::errors::MechanismError;
pub use crate::mechanism::kind::Kind;
pub use crate::mechanism::parsedmechanism::ParsedMechanism;
pub use crate::mechanism::qualifier::Qualifier;

use crate::helpers;
use ipnetwork::{IpNetwork, IpNetworkError};

use std::{convert::TryFrom, str::FromStr};

/// Stores its [`Kind`](Kind), [`Qualifier`](Qualifier), and its `Value`
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
/// # use decon_spf::mechanism::Mechanism;
/// let a: Mechanism<String> = "a".parse().unwrap();
/// assert_eq!(a.kind().is_a(), true);
///
/// if let Ok(mx) = "mx".parse::<Mechanism<String>>() {
///   assert_eq!(mx.kind().is_mx(), true);
/// }
/// if let Ok(mx2) = "-mx:example.com".parse::<Mechanism<String>>() {
///   assert_eq!(mx2.qualifier().is_fail(), true);
///   assert_eq!(mx2.to_string(), "-mx:example.com");
/// }
///
///```
impl FromStr for Mechanism<String> {
    type Err = MechanismError;

    fn from_str(s: &str) -> Result<Mechanism<String>, Self::Err> {
        // A String ending wiith either ':' or "/" is always invalid.
        if s.ends_with(':') || s.ends_with('/') {
            return Err(MechanismError::InvalidMechanismFormat(s.to_string()));
        };
        if s.contains("ip4:") || s.contains("ip6:") {
            return Err(MechanismError::InvalidMechanismFormat(s.to_string()));
        }
        let mut m: Option<Mechanism<String>> = None;

        if s.contains("redirect=") {
            let mut items = s.rsplit('=');
            if let Some(rrdata) = items.next() {
                m = Some(Mechanism::generic_inclusive(
                    Kind::Redirect,
                    Qualifier::Pass,
                    Some(rrdata.to_string()),
                ));
            }
        } else if s.contains("include:") {
            let qualifier_and_modified_str = helpers::return_and_remove_qualifier(s, 'i');
            if let Some(rrdata) = s.rsplit(':').next() {
                m = Some(Mechanism::generic_inclusive(
                    Kind::Include,
                    qualifier_and_modified_str.0,
                    Some(rrdata.to_string()),
                ));
            }
        } else if s.ends_with("all") && (s.len() == 3 || s.len() == 4) {
            m = Some(Mechanism::all(
                helpers::return_and_remove_qualifier(s, 'a').0,
            ));
        } else if let Some(a_mechanism) = helpers::capture_matches(s, Kind::A) {
            m = Some(a_mechanism);
        } else if let Some(mx_mechanism) = helpers::capture_matches(s, Kind::MX) {
            m = Some(mx_mechanism);
        } else if let Some(ptr_mechanism) = helpers::capture_matches(s, Kind::Ptr) {
            m = Some(ptr_mechanism);
        } else if let Some(exists_mechanism) = helpers::capture_matches(s, Kind::Exists) {
            if !exists_mechanism.raw().contains('/') {
                m = Some(exists_mechanism);
            }
        }
        if let Some(value) = m {
            #[cfg(feature = "strict-dns")]
            {
                if !helpers::dns_is_valid(helpers::get_domain_before_slash(&value.raw())) {
                    return Err(MechanismError::InvalidDomainHost(value.raw()));
                }
            }
            return Ok(value);
        }
        Err(MechanismError::InvalidMechanismFormat(s.to_string()))
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
/// # use decon_spf::mechanism::{Mechanism, MechanismError};
/// # use ipnetwork::IpNetwork;
/// let ip4: Mechanism<IpNetwork> = "ip4:203.32.160.0/24".parse().unwrap();
/// assert_eq!(ip4.kind().is_ip_v4(), true);
///
/// let ip6 = "ip6:2001:4860:4000::/36".parse::<Mechanism<IpNetwork>>().unwrap();
/// assert_eq!(ip6.kind().is_ip_v6(), true);
///
/// let bad_ip4: Result<Mechanism<IpNetwork>, MechanismError> = "ip4:203.32.160.0/33".parse();
/// assert_eq!(bad_ip4.unwrap_err().to_string(), "invalid address: 203.32.160.0/33");
///
/// let ip6_but_ip4: Result<Mechanism<IpNetwork>, MechanismError> = "ip6:203.32.160.0/24".parse();
/// let err = ip6_but_ip4.unwrap_err();
/// assert_eq!(err, MechanismError::NotIP6Network("203.32.160.0/24".to_string()));
/// assert_eq!(err.to_string(), "203.32.160.0/24 is not an ip6 network");
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
            // Consider changing this to if let Some() = {}
            let parsed = raw_ip.unwrap().parse();
            if let Ok(parsed_ip) = parsed {
                let ip: IpNetwork = parsed_ip;
                if ip.is_ipv4() && kind.is_ip_v4() {
                    return Ok(Mechanism::generic_inclusive(
                        kind,
                        qualifier_and_modified_str.0,
                        Some(ip),
                    ));
                } else if ip.is_ipv4() && !kind.is_ip_v4() {
                    return Err(MechanismError::NotIP6Network(ip.to_string()));
                } else if ip.is_ipv6() && kind.is_ip_v6() {
                    return Ok(Mechanism::generic_inclusive(
                        kind,
                        qualifier_and_modified_str.0,
                        Some(ip),
                    ));
                } else if ip.is_ipv6() && !kind.is_ip_v6() {
                    return Err(MechanismError::NotIP4Network(ip.to_string()));
                };
            } else {
                return Err(MechanismError::InvalidIPNetwork(
                    parsed.unwrap_err().to_string(),
                ));
            };
        }
        // Catch all. This is not an ip4 or ip6 spf string.
        Err(MechanismError::InvalidMechanismFormat(s.to_string()))
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
    pub fn generic_inclusive(kind: Kind, qualifier: Qualifier, mechanism: Option<T>) -> Self {
        Self {
            kind,
            qualifier,
            rrdata: mechanism,
        }
    }
    #[doc(hidden)]
    pub fn new(kind: Kind, qualifier: Qualifier) -> Self {
        Self {
            kind,
            qualifier,
            rrdata: None,
        }
    }
    /// Check mechanism is pass
    pub fn is_pass(&self) -> bool {
        self.qualifier == Qualifier::Pass
    }
    /// check mechanism is fail
    pub fn is_fail(&self) -> bool {
        self.qualifier == Qualifier::Fail
    }
    /// Check mechanism is softfail
    pub fn is_softfail(&self) -> bool {
        self.qualifier == Qualifier::SoftFail
    }
    /// Check mechanism is neutral
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
    #[deprecated(note = "This will be depreciated in 0.3.0. Please use `redirect()` instead")]
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::Redirect, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Redirect`
    pub fn redirect(qualifier: Qualifier, rrdata: &str) -> Result<Self, MechanismError> {
        Ok(Mechanism::new(Kind::Redirect, qualifier).with_rrdata(rrdata)?)
    }
    /// Create a new Mechanism struct of `A` with no string value.
    #[deprecated(note = "This will be depreciated in 0.3.0. Please use `a()` instead")]
    pub fn new_a_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::generic_inclusive(Kind::A, qualifier, None)
    }

    /// Create a new Mechanism struct of `A` with string value.
    #[deprecated(
        note = "This will be depreciated in 0.3.0. Please use `a().with_rrdata()` instead"
    )]
    pub fn new_a_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::A, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `A`
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// # #[cfg(feature = "strict-dns")]
    /// # use decon_spf::mechanism::MechanismError;
    /// // New `A` without rrdata.
    /// let m = Mechanism::new_a_without_mechanism(Qualifier::Pass);
    /// assert_eq!(m.kind().is_a(), true);
    /// assert_eq!(m.raw(), "a".to_string());
    /// assert_eq!(m.mechanism().is_none(), true);
    /// // Create `A` with rrdata
    /// if let Ok(m_with_rrdata) = Mechanism::a(Qualifier::Pass)
    ///                                                .with_rrdata("example.com") {
    ///   assert_eq!(m_with_rrdata.raw(), "example.com".to_string());
    ///   assert_eq!(m_with_rrdata.to_string(), "a:example.com".to_string());
    /// }
    /// // Create `A` with bad rrdata and `strict-dns` is disabled
    /// if let Ok(bad_rrdata) = Mechanism::a(Qualifier::Pass)
    ///                                             .with_rrdata("example.xx") {
    ///   assert_eq!(bad_rrdata.raw(), "example.xx".to_string());
    ///   assert_eq!(bad_rrdata.to_string(), "a:example.xx".to_string());
    /// }
    /// // Create `A` with bad rrdata and `strict-dns` is enabled
    /// # #[cfg(feature = "strict-dns")] {
    /// if let Err(bad_rrdata) = Mechanism::a(Qualifier::Pass)
    ///                                              .with_rrdata("example.xx") {
    ///   assert_eq!(bad_rrdata, MechanismError::InvalidDomainHost("example.xx".to_string()));
    /// }
    /// # }
    ///```
    pub fn a(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::A, qualifier)
    }
    /// Create a new Mechanism struct of `MX` without string value.
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `mx()` instead")]
    pub fn new_mx_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::generic_inclusive(Kind::MX, qualifier, None)
    }

    /// Create a new Mechanism struct of `MX`
    #[deprecated(
        note = "This will  be depreciated in 0.3.0. Please use `mx().with_rrdata()` instead"
    )]
    pub fn new_mx_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::MX, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `MX`
    ///
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// // without rrdata
    /// let mx = Mechanism::mx(Qualifier::Pass);
    /// assert_eq!(mx.kind().is_mx(), true);
    /// assert_eq!(mx.raw(), "mx");
    /// // with rrdata
    /// if let Ok(mx) = Mechanism::mx(Qualifier::Pass)
    ///                               .with_rrdata("example.com") {
    ///   assert_eq!(mx.kind().is_mx(), true);
    ///   assert_eq!(mx.raw(), "example.com".to_string());
    ///   assert_eq!(mx.to_string(), "mx:example.com".to_string());
    /// }
    /// ```
    pub fn mx(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::MX, qualifier)
    }

    /// Create a new Mechanism struct of `Include`
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `include()` instead")]
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::Include, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Include`
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let include = Mechanism::include(Qualifier::Pass,
    ///                                         "example.com").unwrap();
    /// assert_eq!(include.qualifier().as_str(), "");
    /// assert_eq!(include.raw(), "example.com");
    /// assert_eq!(include.to_string(), "include:example.com");
    /// let include2 = Mechanism::include(Qualifier::SoftFail,
    ///                                          "example.com").unwrap();
    /// assert_eq!(include2.to_string(), "~include:example.com")
    /// ```
    pub fn include(qualifier: Qualifier, rrdata: &str) -> Result<Self, MechanismError> {
        Ok(Mechanism::new(Kind::Include, qualifier).with_rrdata(rrdata)?)
    }

    /// Create a new Mechanism struct of `Ptr` with no value
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `ptr()` instead")]
    pub fn new_ptr_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::generic_inclusive(Kind::Ptr, qualifier, None)
    }

    /// Create a new Mechanism struct of `Ptr`
    #[deprecated(
        note = "This will  be depreciated in 0.3.0. Please use `ptr().with_rrdata()` instead"
    )]
    pub fn new_ptr_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::Ptr, qualifier, Some(mechanism))
    }
    /// Create a new Mechanism struct of `Ptr`
    /// # Example:
    /// ```rust
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// // without rrdata
    /// let ptr = Mechanism::ptr(Qualifier::Fail);
    /// assert_eq!(ptr.to_string(), "-ptr");
    /// // with rrdata
    /// let ptr = Mechanism::ptr(Qualifier::Fail)
    ///                                 .with_rrdata("example.com").unwrap();
    /// assert_eq!(ptr.to_string(), "-ptr:example.com");
    /// ```
    pub fn ptr(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::Ptr, qualifier)
    }

    /// Create a new Mechanism struct of `Exists`
    #[deprecated(
        note = "This will  be depreciated in 0.3.0. Please use `exists().with_rrdata()` instead"
    )]
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::generic_inclusive(Kind::Exists, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Exists`
    pub fn exists(qualifier: Qualifier, rrdata: &str) -> Result<Self, MechanismError> {
        Ok(Mechanism::new(Kind::Exists, qualifier).with_rrdata(rrdata)?)
    }
    /// Set the rrdata for Mechanism
    /// # Note: This is only applicable for Mechanisms of `A`, `MX` and `Ptr`.  
    /// All other Mechanism types require `rrdata` to be set. That is to say that `rrdata` is
    /// **optional** for `A`, `MX` and `PTR`  
    /// See: [`a`](Mechanism<String>::a) for an example.
    pub fn with_rrdata(mut self, rrdata: impl Into<String>) -> Result<Self, MechanismError> {
        #[cfg(feature = "strict-dns")]
        {
            match self.kind() {
                Kind::A | Kind::MX | Kind::Include | Kind::Ptr | Kind::Exists => {
                    if !helpers::dns_is_valid(helpers::get_domain_before_slash(&rrdata)) {
                        return Err(MechanismError::InvalidDomainHost(rrdata.into()));
                    };
                }
                _ => {}
            };
        }
        match self.kind() {
            // Ensure that `All` is always None even if with_rrdata() is called
            Kind::All => self.rrdata = None,
            _ => self.rrdata = Some(rrdata.into()),
        }
        Ok(self)
    }
    /// Create a new Mechanism struct of `All`
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `all()` instead")]
    pub fn new_all(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::All, qualifier)
    }

    /// Create a new Mechanism struct of `All`
    pub fn all(qualifier: Qualifier) -> Self {
        Mechanism::new(Kind::All, qualifier)
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

    fn build_string(&self) -> String {
        let mut mechanism_str = String::new();
        let tmp_mechanism_str;
        if self.qualifier != Qualifier::Pass {
            mechanism_str.push_str(self.qualifier.as_str());
        };
        mechanism_str.push_str(self.kind().as_str());
        if let Some(ref rrdata) = self.rrdata {
            tmp_mechanism_str = rrdata.as_str();
        } else {
            tmp_mechanism_str = "";
        }
        match self.kind {
            Kind::A | Kind::MX => {
                // This must be starting with 'domain.com' So prepend ':'
                if !tmp_mechanism_str.is_empty() && !tmp_mechanism_str.starts_with('/') {
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

/// Provide to_string for Mechanism<String>

impl std::fmt::Display for Mechanism<String> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_string())
    }
}

impl From<IpNetworkError> for MechanismError {
    fn from(err: IpNetworkError) -> Self {
        MechanismError::InvalidIPNetwork(err.to_string())
    }
}

impl Mechanism<IpNetwork> {
    /// Create a new V4 or V6 Mechanism<IpNetwork>  
    #[deprecated(note = "This will be depreciated in 0.3.0. Please use `ip()` instead")]
    pub fn new_ip(qualifier: Qualifier, mechanism: IpNetwork) -> Mechanism<IpNetwork> {
        Mechanism::ip(qualifier, mechanism)
    }
    /// Create a new V4 or V6 Mechanism from a string representation.
    ///```
    /// # use decon_spf::mechanism::{Mechanism, MechanismError};
    /// let string = "+ip4:203.32.160.0/24";
    /// if let Ok(m) = Mechanism::ip_from_string(&string) {
    ///   assert_eq!(m.raw(), "203.32.160.0/24");
    ///   assert_eq!(m.to_string(), "ip4:203.32.160.0/24");
    /// }
    ///```
    pub fn ip_from_string(string: &str) -> Result<Mechanism<IpNetwork>, MechanismError> {
        Ok(Mechanism::<IpNetwork>::from_str(string)?)
    }

    /// Create a new V4 or V6 Mechanism<IpNetwork>  
    /// Will correctly set its `kind` based on the `IpNetwork` type.
    ///
    /// # Examples:
    /// ```
    /// # use ipnetwork::IpNetwork;
    /// use decon_spf::mechanism::{Mechanism, Qualifier};
    ///
    /// // Requires: use ipnetwork::IpNetwork;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let mechanism = Mechanism::ip(Qualifier::Pass, ip);
    /// assert_eq!(mechanism.kind().is_ip_v4(), true);
    /// assert_eq!(mechanism.raw(), "192.168.11.0/24".to_string());
    /// assert_eq!(mechanism.as_network().to_string(), "192.168.11.0/24".to_string());
    /// assert_eq!(mechanism.as_network().prefix(), 24);
    ///
    /// // This section does not require use of ipnetwork::IpNetwork;
    /// let mechanism_ip4 = Mechanism::ip(Qualifier::Pass,
    ///                                       "203.32.160.0/23".parse().unwrap());
    /// assert_eq!(mechanism_ip4.kind().is_ip(), true);
    /// assert_eq!(mechanism_ip4.kind().is_ip_v4(), true);
    /// assert_eq!(mechanism_ip4.to_string(), "ip4:203.32.160.0/23".to_string());
    /// let mechanism_ip6 = Mechanism::ip(Qualifier::Pass,
    ///                                       "2001:4860:4000::/36".parse().unwrap());
    /// assert_eq!(mechanism_ip6.kind().is_ip(), true);
    /// assert_eq!(mechanism_ip6.kind().is_ip_v6(),true);
    /// assert_eq!(mechanism_ip6.to_string(), "ip6:2001:4860:4000::/36".to_string());
    ///```
    pub fn ip(qualifier: Qualifier, rrdata: IpNetwork) -> Mechanism<IpNetwork> {
        if rrdata.is_ipv4() {
            Mechanism::ip4(qualifier, rrdata)
        } else {
            Mechanism::ip6(qualifier, rrdata)
        }
    }

    /// Create a new Mechanism<IpNetwork> of IP4
    #[doc(hidden)]
    #[allow(dead_code)]
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `ip4()` instead")]
    fn new_ip4(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::generic_inclusive(Kind::IpV4, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism<IpNetwork> of IP4
    fn ip4(qualifier: Qualifier, rrdata: IpNetwork) -> Self {
        Mechanism::generic_inclusive(Kind::IpV4, qualifier, Some(rrdata))
    }
    /// Create a new Mechanism<IpNetwork> of IP6
    #[doc(hidden)]
    #[allow(dead_code)]
    #[deprecated(note = "This will  be depreciated in 0.3.0. Please use `ip6()` instead")]
    fn new_ip6(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::generic_inclusive(Kind::IpV6, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism<IpNetwork> of IP6
    fn ip6(qualifier: Qualifier, rrdata: IpNetwork) -> Self {
        Mechanism::generic_inclusive(Kind::IpV6, qualifier, Some(rrdata))
    }
    /// Returns the simple string representation of the mechanism
    /// # Example
    ///
    ///```
    /// use ipnetwork::IpNetwork;
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = Mechanism::ip(Qualifier::Pass, ip);
    /// assert_eq!(ip_mechanism.raw(), "192.168.11.0/24");
    /// assert_eq!(ip_mechanism.kind().is_ip(), true);
    ///```
    ///
    pub fn raw(&self) -> String {
        // Consider striping ':' and "/" if they are the first characters.
        self.rrdata.unwrap().to_string()
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

    /// Returns a reference to the mechanism as an `IpNetwork`
    pub fn as_network(&self) -> &IpNetwork {
        self.rrdata.as_ref().unwrap()
    }
}

/// Provide to_string for Mechanism<IpNetwork>
impl std::fmt::Display for Mechanism<IpNetwork> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_string())
    }
}
