//! A struct created either by having an existing SPF record `parsed` or programmatically created.

use crate::spf::kinds::MechanismKind;
use crate::spf::qualifier::Qualifier;
use ipnetwork::IpNetwork;

/// Stores its `kind`, `Qualifier` and its `mechanism`
#[derive(Debug, Clone)]
pub struct Mechanism<T> {
    kind: MechanismKind,
    qualifier: Qualifier,
    rr_value: Option<T>,
}

impl<T> Mechanism<T> {
    //! These are the generic methods for the struct of Mechanism.  
    //! All the following methods can be used on any struct of type Mechanism.
    #[doc(hidden)]
    pub fn new(kind: MechanismKind, qualifier: Qualifier, mechanism: Option<T>) -> Self {
        Self {
            kind,
            qualifier,
            rr_value: mechanism,
        }
    }
    /// check is mechanism is pass
    pub fn is_pass(&self) -> bool {
        self.qualifier == Qualifier::Pass
    }
    /// check is mechanism is fail
    pub fn is_fail(&self) -> bool {
        self.qualifier == Qualifier::Fail
    }
    /// check is mechanism is softfail
    pub fn is_softfail(&self) -> bool {
        self.qualifier == Qualifier::SoftFail
    }
    /// check is mechanism is neutral
    pub fn is_neutral(&self) -> bool {
        self.qualifier == Qualifier::Neutral
    }
    /// Returns a reference to the Mechanism's MechanismKind
    pub fn kind(&self) -> &MechanismKind {
        &self.kind
    }
    /// Returns a reference to the Mechanism's Qualifier
    pub fn qualifier(&self) -> &Qualifier {
        &self.qualifier
    }
    /// Returns a reference to the Mechanism's Value.
    /// This could return a `String` or `IpNetwork`
    pub fn mechanism(&self) -> &Option<T> {
        &self.rr_value
    }
}

impl Mechanism<String> {
    /// create a new Mechanism struct of `Redirect`
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Redirect, qualifier, Some(mechanism))
    }

    /// Document me.
    pub fn new_a_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::A, qualifier, None)
    }

    /// create a new Mechanism struct of `A`
    /// # Example:
    /// ```rust
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_a = Mechanism::new_a_with_mechanism(Qualifier::Pass, String::from("example.com"));
    /// assert_eq!(mechanism_of_a.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_a.raw(), "example.com");
    /// assert_eq!(mechanism_of_a.string(), "a:example.com");
    /// let blank_a = Mechanism::new_a_without_mechanism(Qualifier::SoftFail);
    /// assert_eq!(blank_a.qualifier().as_str(), "~");
    /// assert_eq!(blank_a.string(), "~a");
    /// ```
    pub fn new_a_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::A, qualifier, Some(mechanism))
    }

    /// Document me
    pub fn new_mx_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::MX, qualifier, None)
    }

    /// create a new Mechanism struct of `MX`
    /// # Example:
    /// ```rust
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_mx = Mechanism::new_mx_with_mechanism(Qualifier::Pass, String::from("example.com"));
    /// assert_eq!(mechanism_of_mx.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_mx.raw(), "example.com");
    /// assert_eq!(mechanism_of_mx.string(), "mx:example.com")
    /// ```
    pub fn new_mx_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::MX, qualifier, Some(mechanism))
    }

    /// create a new Mechanism struct of `Include`
    /// # Example:
    /// ```rust
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_include = Mechanism::new_include(Qualifier::Pass, String::from("example.com"));
    /// assert_eq!(mechanism_of_include.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_include.raw(), "example.com");
    /// assert_eq!(mechanism_of_include.string(), "include:example.com");
    /// let mechanism_of_include2 = Mechanism::new_include(Qualifier::SoftFail, String::from("example.com"));
    /// assert_eq!(mechanism_of_include2.string(), "~include:example.com")
    /// ```
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Include, qualifier, Some(mechanism))
    }

    /// create a new Mechanism struct of `Ptr` with no value
    /// # Example:
    /// ```rust
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_ptr = Mechanism::new_ptr_without_mechanism(Qualifier::Fail);
    /// assert_eq!(mechanism_of_ptr.string(), "-ptr");
    pub fn new_ptr_without_mechanism(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, None)
    }

    /// create a new Mechanism struct of `Ptr`
    /// # Example:
    /// ```rust
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_ptr = Mechanism::new_ptr_with_mechanism(Qualifier::Pass, String::from("example.com"));
    /// assert_eq!(mechanism_of_ptr.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_ptr.raw(), "example.com");
    /// assert_eq!(mechanism_of_ptr.string(), "ptr:example.com");
    pub fn new_ptr_with_mechanism(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, Some(mechanism))
    }

    /// create a new Mechanism struct of `Exists`
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Exists, qualifier, Some(mechanism))
    }

    /// create a new Mechanism struct of `All`
    pub fn new_all(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::All, qualifier, None)
    }

    /// Return the string stored in the attribute `mechanism`
    pub fn raw(&self) -> &str {
        if self.rr_value.is_none() {
            self.kind().as_str()
        } else {
            self.rr_value.as_ref().unwrap()
        }
    }

    /// Rebuild and return the string representation of the given mechanism
    pub fn string(&self) -> String {
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
            MechanismKind::A | MechanismKind::MX => {
                // This must be starting with 'domain.com' So prepend ":"
                if !tmp_mechanism_str.starts_with("/") && tmp_mechanism_str != "" {
                    mechanism_str.push_str(":")
                }
            }
            MechanismKind::Ptr => {
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

impl Mechanism<IpNetwork> {
    /// Create a new Mechanism<IpNetwork>
    /// Will correctly set its `kind` based on the `IpNetwork` type.
    #[doc(hidden)]
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
        Mechanism::new(MechanismKind::IpV4, qualifier, Some(mechanism))
    }

    /// Create a new Mechanism<IpNetwork> of IP6
    #[doc(hidden)]
    pub fn new_ip6(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::new(MechanismKind::IpV6, qualifier, Some(mechanism))
    }

    /// Returns the simple string representation of the mechanism
    /// # Example
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = Mechanism::new_ip4(Qualifier::Pass, ip);
    /// assert_eq!(ip_mechanism.raw(), "192.168.11.0/24");
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
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = Mechanism::new_ip4(Qualifier::Pass, ip);
    /// assert_eq!(ip_mechanism.string(), "ip4:192.168.11.0/24");
    /// assert_eq!(ip_mechanism.as_network(), &ip);
    /// ```
    ///
    pub fn string(&self) -> String {
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
