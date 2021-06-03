use crate::spf::kinds::MechanismKind;
use crate::spf::qualifier::Qualifier;
use ipnetwork::IpNetwork;

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
    pub fn is_pass(&self) -> bool {
        self.qualifier == Qualifier::Pass
    }
    pub fn is_fail(&self) -> bool {
        self.qualifier == Qualifier::Fail
    }
    pub fn is_softfail(&self) -> bool {
        self.qualifier == Qualifier::SoftFail
    }
    pub fn is_neutral(&self) -> bool {
        self.qualifier == Qualifier::Neutral
    }
    #[doc(hidden)]
    fn mechanism_prefix_from_kind(&self) -> String {
        let push_str = match self.kind {
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
        push_str.to_string()
    }
    /// Returns a reference to the Mechanism's Qualifier
    pub fn qualifier(&self) -> &Qualifier {
        &self.qualifier
    }
    /// Returns a reference to the Mechanism's Value of Type T.
    pub fn mechanism(&self) -> &T {
        &self.mechanism
    }
}

impl Mechanism<String> {
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Include, qualifier, mechanism)
    }
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Redirect, qualifier, mechanism)
    }
    pub fn new_a(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::A, qualifier, mechanism)
    }
    pub fn new_mx(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::MX, qualifier, mechanism)
    }
    pub fn new_ptr(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, mechanism)
    }
    pub fn new_ptr_blank(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::Ptr, qualifier, String::new())
    }
    pub fn new_exists(qualifier: Qualifier, mechanism: String) -> Self {
        Mechanism::new(MechanismKind::Exists, qualifier, mechanism)
    }
    pub fn new_all(qualifier: Qualifier) -> Self {
        Mechanism::new(MechanismKind::All, qualifier, String::from("all"))
    }
    pub fn raw(&self) -> &String {
        &self.mechanism
    }
    /// Rebuild and return the string representation of the given mechanism
    pub fn string(&self) -> String {
        let mut txt = String::new();
        if self.qualifier != Qualifier::Pass {
            txt.push_str(self.qualifier.get_str());
        };
        match self.kind {
            MechanismKind::A | MechanismKind::MX | MechanismKind::Ptr | MechanismKind::All => {
                if self.mechanism.starts_with(":") || self.mechanism.starts_with("/") {
                    txt.push_str(self.mechanism_prefix_from_kind().as_str());
                }
            }
            _ => txt.push_str(self.mechanism_prefix_from_kind().as_str()),
        };
        txt.push_str(self.mechanism.as_str());
        txt
    }
}

impl Mechanism<IpNetwork> {
    pub fn new_ip(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        if mechanism.is_ipv4() {
            Mechanism::new_ip4(qualifier, mechanism)
        } else {
            Mechanism::new_ip6(qualifier, mechanism)
        }
    }
    pub fn new_ip4(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        Mechanism::new(MechanismKind::IpV4, qualifier, mechanism)
    }
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
    /// ```
    ///
    pub fn string(&self) -> String {
        let mut txt = String::new();
        if self.qualifier != Qualifier::Pass {
            txt.push_str(self.qualifier.get_str());
        };
        txt.push_str(self.mechanism_prefix_from_kind().as_str());
        txt.push_str(self.mechanism.to_string().as_str());
        txt
    }
    pub fn as_network(&self) -> &IpNetwork {
        &self.mechanism
    }
}