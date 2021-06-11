//! A struct created either by having an existing SPF record `parsed` or programmatically created.

use crate::spf::kinds::MechanismKind;
use crate::spf::qualifier::Qualifier;
use ipnetwork::IpNetwork;

/// Stores its `kind`, `Qualifier` and its `mechanism`
#[derive(Debug, Clone)]
pub struct Mechanism<T> {
    kind: MechanismKind,
    qualifier: Qualifier,
    mechanism: T,
}

impl<T> Mechanism<T> {
    //! These are the generic methods for the struct of Mechanism.  
    //! All the following methods can be used on any struct of type Mechanism.
    #[doc(hidden)]
    pub fn new(kind: MechanismKind, qualifier: Qualifier, mechanism: T) -> Self {
        Self {
            kind,
            qualifier,
            mechanism,
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
    pub fn mechanism(&self) -> &T {
        &self.mechanism
    }
}

impl Mechanism<String> {
    /// create a new Mechanism struct of `Redirect`
    #[doc(hidden)]
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Redirect, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `A`
    /// # Example:
    /// ```
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::Mechanism;
    /// let mechanism_of_a = Mechanism::new_a(Qualifier::Pass, String::from(":example.com"));
    /// assert_eq!(mechanism_of_a.qualifier().as_str(), "");
    /// assert_eq!(mechanism_of_a.raw(), "example.com");
    /// assert_eq!(mechanism_of_a.string(), "a:example.com")
    /// ```
    #[doc(hidden)]
    pub fn new_a(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::A, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `MX`
    #[doc(hidden)]
    pub fn new_mx(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::MX, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `Include`
    #[doc(hidden)]
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Include, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `Ptr`
    #[doc(hidden)]
    pub fn new_ptr(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `Ptr` with no value
    #[doc(hidden)]
    pub fn new_ptr_blank(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, String::new())
    }
    /// create a new Mechanism struct of `Exists`
    #[doc(hidden)]
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Exists, qualifier, mechanism)
    }
    /// create a new Mechanism struct of `All`
    #[doc(hidden)]
    pub fn new_all(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::All, qualifier, String::new())
    }
    /// Return the string stored inthe attribute `mechanism`
    pub fn raw(&self) -> &str {
        if self.mechanism == "" {
            self.kind().as_str()
        } else if self.mechanism.starts_with(":") {
            let mut char = self.mechanism.chars();
            char.next();
            char.as_str()
        } else {
            &self.mechanism
        }
    }
    /// Rebuild and return the string representation of the given mechanism
    pub fn string(&self) -> String {
        let mut mechanism_str = String::new();
        if self.qualifier != Qualifier::Pass {
            mechanism_str.push_str(self.qualifier.as_str());
        };
        mechanism_str.push_str(self.kind().as_str());
        mechanism_str.push_str(self.mechanism.as_str());
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
        Mechanism::new(MechanismKind::IpV4, qualifier, mechanism)
    }
    /// Create a new Mechanism<IpNetwork> of IP6
    #[doc(hidden)]
    pub fn new_ip6(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::new(MechanismKind::IpV6, qualifier, mechanism)
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
        self.mechanism.to_string()
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
        ip_mechanism_str.push_str(self.mechanism.to_string().as_str());
        ip_mechanism_str
    }
    /// Returns the mechanism as an `IpNetwork`
    pub fn as_network(&self) -> &IpNetwork {
        &self.mechanism
    }
}
