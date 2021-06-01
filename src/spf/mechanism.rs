use crate::spf::kinds::MechanismKind;
use crate::spf::qualifier::Qualifier;
use ipnetwork::IpNetwork;

#[derive(Debug, Clone)]
pub struct SpfMechanism<T> {
    kind: MechanismKind,
    qualifier: Qualifier,
    mechanism: T,
}

impl<T> SpfMechanism<T> {
    //! These are the generic methods for the struct of SpfMechanism.  
    //! All the following methods can be used on any struct of type SpfMechanism.
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
            MechanismKind::A => "",
            MechanismKind::MX => "",
            MechanismKind::IpV4 => "ip4:",
            MechanismKind::IpV6 => "ip6:",
            MechanismKind::All => "all",
        };
        push_str.to_string()
    }
    pub fn qualifier(&self) -> &Qualifier {
        &self.qualifier
    }
    pub fn mechanism(&self) -> &T {
        &self.mechanism
    }
}

impl SpfMechanism<String> {
    pub fn new_include(qualifier: Qualifier, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Include, qualifier, mechanism)
    }
    pub fn new_redirect(qualifier: Qualifier, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Redirect, qualifier, mechanism)
    }
    pub fn new_a(qualifier: Qualifier, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::A, qualifier, mechanism)
    }
    pub fn new_mx(qualifier: Qualifier, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::MX, qualifier, mechanism)
    }
    pub fn new_all(qualifier: Qualifier) -> Self {
        SpfMechanism::new(MechanismKind::All, qualifier, String::new())
    }
    /// Rebuild and return the string representation of the given mechanism
    pub fn string(&self) -> String {
        let mut txt = String::new();
        if self.qualifier != Qualifier::Pass {
            txt.push_str(self.qualifier.get_str());
        };
        txt.push_str(self.mechanism_prefix_from_kind().as_str());
        txt.push_str(self.mechanism.as_str());
        txt
    }
    pub fn raw(&self) -> &String {
        &self.mechanism
    }
}
#[cfg(test)]
#[allow(non_snake_case)]
mod SpfMechanismString {

    use super::Qualifier;
    use super::SpfMechanism;
    #[test]
    fn test_redirect() {
        let redirect =
            SpfMechanism::new_redirect(Qualifier::Pass, String::from("_spf.example.com"));
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.raw(), "_spf.example.com");
        assert_eq!(redirect.string(), "redirect=_spf.example.com");
    }
    #[test]
    fn test_include_pass() {
        let include = SpfMechanism::new_include(Qualifier::Pass, String::from("_spf.test.com"));
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.raw(), "_spf.test.com");
        assert_eq!(include.string(), "include:_spf.test.com");
    }
    #[test]
    fn test_include_fail() {
        let include = SpfMechanism::new_include(Qualifier::Fail, String::from("_spf.test.com"));
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.string(), "-include:_spf.test.com");
    }
    #[test]
    fn test_include_softfail() {
        let include = SpfMechanism::new_include(Qualifier::SoftFail, String::from("_spf.test.com"));
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.string(), "~include:_spf.test.com");
    }
    #[test]
    fn test_include_neutral() {
        let include = SpfMechanism::new_include(Qualifier::Neutral, String::from("_spf.test.com"));
        assert_eq!(include.is_neutral(), true);
        assert_eq!(include.string(), "?include:_spf.test.com");
    }
    #[test]
    fn test_new_a() {
        let a_mechanism = SpfMechanism::new_a(Qualifier::Fail, "a".to_string());
        assert_eq!(a_mechanism.is_fail(), true);
        assert_eq!(a_mechanism.raw(), "a");
    }
}

impl SpfMechanism<IpNetwork> {
    pub fn new_ip(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        if mechanism.is_ipv4() {
            SpfMechanism::new_ip4(qualifier, mechanism)
        } else {
            SpfMechanism::new_ip6(qualifier, mechanism)
        }
    }
    pub fn new_ip4(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV4, qualifier, mechanism)
    }
    pub fn new_ip6(qualifier: Qualifier, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV6, qualifier, mechanism)
    }
    // Returns the mechanism string representation of an IP4/6 mechanism.
    // # Example
    ///
    /// ```
    /// use ipnetwork::IpNetwork;
    /// use decon_spf::spf::qualifier::Qualifier;
    /// use decon_spf::spf::mechanism::SpfMechanism;
    /// let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
    /// let ip_mechanism = SpfMechanism::new_ip4(Qualifier::Pass, ip);
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
    pub fn raw(&self) -> String {
        //! Returns the simple string representation of the mechanism
        //! # Example
        //!
        //! ```
        //! use ipnetwork::IpNetwork;
        //! use decon_spf::spf::qualifier::Qualifier;
        //! use decon_spf::spf::mechanism::SpfMechanism;
        //! let ip: IpNetwork = "192.168.11.0/24".parse().unwrap();
        //! let ip_mechanism = SpfMechanism::new_ip4(Qualifier::Pass, ip);
        //! assert_eq!(ip_mechanism.raw(), "192.168.11.0/24");
        //! ```
        //!
        self.mechanism.to_string()
    }
    pub fn as_network(&self) -> &IpNetwork {
        &self.mechanism
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod SpfMechanismIpNetwork {

    use super::Qualifier;
    use super::SpfMechanism;

    #[test]
    fn test_ip4_pass() {
        let ip4_pass = SpfMechanism::new_ip4(Qualifier::Pass, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_pass.is_pass(), true);
        assert_eq!(ip4_pass.raw(), "203.32.160.10/32");
        assert_eq!(ip4_pass.string(), "ip4:203.32.160.10/32");
        assert_eq!(ip4_pass.mechanism().ip().to_string(), "203.32.160.10");
        assert_eq!(ip4_pass.mechanism().prefix().to_string(), "32");
        assert_eq!(ip4_pass.mechanism().network().to_string(), "203.32.160.10");
    }
    #[test]
    fn test_ip4_fail() {
        let ip4_fail = SpfMechanism::new_ip4(Qualifier::Fail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_fail.is_fail(), true);
        assert_eq!(ip4_fail.string(), "-ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_softfail() {
        let ip4_softfail =
            SpfMechanism::new_ip4(Qualifier::SoftFail, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_softfail.is_softfail(), true);
        assert_eq!(ip4_softfail.string(), "~ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_neutral() {
        let ip4_neutral =
            SpfMechanism::new_ip4(Qualifier::Neutral, "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_neutral.is_neutral(), true);
        assert_eq!(ip4_neutral.string(), "?ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip6_pass() {
        let ip_pass =
            SpfMechanism::new_ip6(Qualifier::Pass, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_pass.is_pass(), true);
        assert_eq!(ip_pass.raw(), "2001:4860:4000::/36");
        assert_eq!(ip_pass.string(), "ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_fail() {
        let ip_fail =
            SpfMechanism::new_ip6(Qualifier::Fail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_fail.is_fail(), true);
        assert_eq!(ip_fail.string(), "-ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_softfail() {
        let ip_softfail =
            SpfMechanism::new_ip6(Qualifier::SoftFail, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_softfail.is_softfail(), true);
        assert_eq!(ip_softfail.string(), "~ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_neutral() {
        let ip_neutral =
            SpfMechanism::new_ip6(Qualifier::Neutral, "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_neutral.is_neutral(), true);
        assert_eq!(ip_neutral.string(), "?ip6:2001:4860:4000::/36");
    }
}
