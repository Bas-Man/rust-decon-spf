use crate::dns::spf::kinds::MechanismKind;
use ipnetwork::IpNetwork;

#[derive(Debug, Clone)]
pub struct SpfMechanism<T> {
    kind: MechanismKind,
    qualifier: char,
    mechanism: T,
}

impl SpfMechanism<String> {
    pub fn new_include(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Include, qualifier, mechanism)
    }
    pub fn new_redirect(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Redirect, qualifier, mechanism)
    }
    pub fn new_all(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::All, qualifier, mechanism)
    }
    pub fn as_mechanism(&self) -> String {
        // rebuild and return the string representation of a include, redirect, a or mx mechanism
        let mut txt = String::new();
        if self.qualifier != '+' {
            txt.push(self.qualifier);
        };
        if self.kind.is_all() {
            txt.push_str("all")
        } else {
            txt.push_str(self.mechanism_prefix_from_kind().as_str());
            txt.push_str(self.mechanism.as_str());
        }
        txt
    }
    pub fn as_string(&self) -> &String {
        &self.mechanism
    }
}
#[cfg(test)]
mod SpfMechanismString {

    use super::SpfMechanism;
    #[test]
    fn test_redirect() {
        let redirect = SpfMechanism::new_redirect('+', String::from("_spf.example.com"));
        assert_eq!(redirect.is_pass(), true);
        assert_eq!(redirect.as_string(), "_spf.example.com");
        assert_eq!(redirect.as_mechanism(), "redirect=_spf.example.com");
    }
    #[test]
    fn test_include_pass() {
        let include = SpfMechanism::new_include('+', String::from("_spf.test.com"));
        assert_eq!(include.is_pass(), true);
        assert_eq!(include.as_string(), "_spf.test.com");
        assert_eq!(include.as_mechanism(), "include:_spf.test.com");
    }
    #[test]
    fn test_include_fail() {
        let include = SpfMechanism::new_include('-', String::from("_spf.test.com"));
        assert_eq!(include.is_fail(), true);
        assert_eq!(include.as_mechanism(), "-include:_spf.test.com");
    }
    #[test]
    fn test_include_softfail() {
        let include = SpfMechanism::new_include('~', String::from("_spf.test.com"));
        assert_eq!(include.is_softfail(), true);
        assert_eq!(include.as_mechanism(), "~include:_spf.test.com");
    }
    #[test]
    fn test_include_neutral() {
        let include = SpfMechanism::new_include('?', String::from("_spf.test.com"));
        assert_eq!(include.is_neutral(), true);
        assert_eq!(include.as_mechanism(), "?include:_spf.test.com");
    }
}

impl SpfMechanism<IpNetwork> {
    pub fn new_ip4(qualifier: char, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV4, qualifier, mechanism)
    }
    pub fn new_ip6(qualifier: char, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV6, qualifier, mechanism)
    }
    pub fn as_mechanism(&self) -> String {
        // rebuild and return the string represensation of a include, redirect mechanism
        let mut txt = String::new();
        if self.qualifier != '+' {
            txt.push(self.qualifier);
        } else {
            // Do nothing omitting '+'
        }
        txt.push_str(self.mechanism_prefix_from_kind().as_str());
        txt.push_str(self.mechanism.to_string().as_str());
        txt
    }
    pub fn as_string(&self) -> String {
        self.mechanism.to_string()
    }
    pub fn as_network(&self) -> &IpNetwork {
        &self.mechanism
    }
}
impl<T> SpfMechanism<T> {
    pub fn new(kind: MechanismKind, qualifier: char, mechanism: T) -> Self {
        Self {
            kind,
            qualifier,
            mechanism,
        }
    }
    pub fn is_pass(&self) -> bool {
        self.qualifier == '+'
    }
    pub fn is_fail(&self) -> bool {
        self.qualifier == '-'
    }
    pub fn is_softfail(&self) -> bool {
        self.qualifier == '~'
    }
    pub fn is_neutral(&self) -> bool {
        self.qualifier == '?'
    }
    fn mechanism_prefix_from_kind(&self) -> String {
        let push_str = match self.kind {
            MechanismKind::Redirect => "redirect=",
            MechanismKind::Include => "include:",
            MechanismKind::A => "a:",   // requires modification
            MechanismKind::MX => "mx:", // requires modication
            MechanismKind::IpV4 => "ip4:",
            MechanismKind::IpV6 => "ip6:",
            MechanismKind::All => "",
        };
        push_str.to_string()
    }
}

#[cfg(test)]
mod SpfMechanismIpNetwork {

    use super::SpfMechanism;

    #[test]
    fn test_ip4_pass() {
        let ip4_pass = SpfMechanism::new_ip4('+', "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_pass.is_pass(), true);
        assert_eq!(ip4_pass.as_string(), "203.32.160.10/32");
        assert_eq!(ip4_pass.as_mechanism(), "ip4:203.32.160.10/32");
        assert_eq!(ip4_pass.as_network().ip().to_string(), "203.32.160.10");
        assert_eq!(ip4_pass.as_network().prefix().to_string(), "32");
        assert_eq!(ip4_pass.as_network().network().to_string(), "203.32.160.10");
    }
    #[test]
    fn test_ip4_fail() {
        let ip4_fail = SpfMechanism::new_ip4('-', "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_fail.is_fail(), true);
        assert_eq!(ip4_fail.as_mechanism(), "-ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_softfail() {
        let ip4_softfail = SpfMechanism::new_ip4('~', "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_softfail.is_softfail(), true);
        assert_eq!(ip4_softfail.as_mechanism(), "~ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip4_neutral() {
        let ip4_neutral = SpfMechanism::new_ip4('?', "203.32.160.10/32".parse().unwrap());
        assert_eq!(ip4_neutral.is_neutral(), true);
        assert_eq!(ip4_neutral.as_mechanism(), "?ip4:203.32.160.10/32");
    }
    #[test]
    fn test_ip6_pass() {
        let ip_pass = SpfMechanism::new_ip6('+', "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_pass.is_pass(), true);
        assert_eq!(ip_pass.as_string(), "2001:4860:4000::/36");
        assert_eq!(ip_pass.as_mechanism(), "ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_fail() {
        let ip_fail = SpfMechanism::new_ip6('-', "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_fail.is_fail(), true);
        assert_eq!(ip_fail.as_mechanism(), "-ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_softfail() {
        let ip_softfail = SpfMechanism::new_ip6('~', "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_softfail.is_softfail(), true);
        assert_eq!(ip_softfail.as_mechanism(), "~ip6:2001:4860:4000::/36");
    }
    #[test]
    fn test_ip6_neutral() {
        let ip_neutral = SpfMechanism::new_ip6('?', "2001:4860:4000::/36".parse().unwrap());
        assert_eq!(ip_neutral.is_neutral(), true);
        assert_eq!(ip_neutral.as_mechanism(), "?ip6:2001:4860:4000::/36");
    }
}
