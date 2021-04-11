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
        } else {
            // Do nothing omitting '+'
        }
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
