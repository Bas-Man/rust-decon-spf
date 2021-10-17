//! A struct created either by having an existing SPF record `parsed` or programmatically created.

use crate::mechanism::Kind;
use crate::mechanism::Qualifier;
use ipnetwork::IpNetwork;

/// Stores its `Kind`, `Qualifier` and its `Value`
#[derive(Debug, Clone)]
pub struct Mechanism<T> {
    kind: Kind,
    qualifier: Qualifier,
    rr_value: Option<T>,
}

impl<T> Mechanism<T> {
    //! These are the generic methods for the struct of Mechanism.  
    //! All the following methods can be used on any struct of type Mechanism.
    #[doc(hidden)]
    pub fn new(kind: Kind, qualifier: Qualifier, mechanism: Option<T>) -> Self {
        Self {
            kind,
            qualifier,
            rr_value: mechanism,
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
        &self.rr_value
    }
}

impl Mechanism<String> {
    /// Create a new Mechanism struct of `Redirect`
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
    pub fn new_ptr_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Ptr, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `Exists`
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(Kind::Exists, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism struct of `All`
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
    pub fn raw(&self) -> &str {
        if self.rr_value.is_none() {
            self.kind().as_str()
        } else {
            self.rr_value.as_ref().unwrap()
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
        if self.rr_value.is_some() {
            tmp_mechanism_str = self.rr_value.as_ref().unwrap().as_str();
        } else {
            tmp_mechanism_str = ""
        }
        match self.kind {
            Kind::A | Kind::MX => {
                // This must be starting with 'domain.com' So prepend ":"
                if !tmp_mechanism_str.starts_with("/") && tmp_mechanism_str != "" {
                    mechanism_str.push_str(":")
                }
            }
            Kind::Ptr => {
                // This Ptr has a domain. Prepend ":"
                if tmp_mechanism_str != "" {
                    mechanism_str.push_str(":")
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
    pub fn new_ip(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
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
    /// # Example
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use decon_spf::mechanism::Qualifier;
    /// use decon_spf::mechanism::Mechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = Mechanism::new_ip4(Qualifier::Pass, ip);
    /// assert_eq!(ip_mechanism.raw(), "192.168.11.0/24");
    /// assert_eq!(ip_mechanism.kind().is_ip(), true);
    /// ```
    ///
    pub fn raw(&self) -> String {
        // Consider striping ":" and "/" if they are the first characters.
        self.rr_value.unwrap().to_string()
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
        ip_mechanism_str.push_str(self.rr_value.unwrap().to_string().as_str());
        ip_mechanism_str
    }

    /// Returns the mechanism as an `IpNetwork`
    pub fn as_network(&self) -> &IpNetwork {
        &self.rr_value.as_ref().unwrap()
    }
}

impl std::fmt::Display for Mechanism<IpNetwork> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_string())
    }
}
