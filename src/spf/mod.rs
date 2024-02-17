//! This module allows you to deconstruct an existing SPF DNS record into its
//! constituent parts.  
//! It is not intended to validate the spf record.

mod errors;
#[cfg(test)]
mod tests;
mod validate;

use crate::core;
use crate::mechanism::Kind;
pub use crate::mechanism::Mechanism;
use crate::mechanism::{Kind, MechanismError};
pub use crate::spf::errors::SpfError;
use ipnetwork::IpNetwork;
// Make this public in the future
use crate::spf::validate::{SpfRfcStandard, SpfValidationResult};
use std::fmt::{Debug, Display, Formatter};
use std::{convert::TryFrom, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Spf<T> {
    source: T,
    version: T,
    redirect_idx: u8,
    all_idx: u8,
    mechanisms: Vec<Mechanism<T>>,
}

impl<T> Spf<T>
where
    T: Default,
    T: Debug,
    T: Display,
{
}

impl Display for Spf<String> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl FromStr for Spf<String> {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;
        validate::check_whitespaces(s)?;

        let mut redirect_idx = 0;
        let mut redirect = false;
        let mut all_idx = 0;
        let mut idx = 0;
        let mut spf = Spf::default();
        let mechanisms = s.split_whitespace();
        for m in mechanisms {
            if m.contains("v=spf1") {
                spf.version = m.to_string();
            } else if m.contains("ip4:") || m.contains("ip6:") {
                let m_ip = m.parse::<Mechanism<IpNetwork>>()?;
                spf.mechanisms.push(m_ip.into());
            } else {
                let m_str = m.parse::<Mechanism<String>>()?;
                match *m_str.kind() {
                    Kind::Redirect => {
                        if !redirect {
                            redirect = true;
                            redirect_idx = idx;
                        } else {
                            return Err(SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
                        }
                    }
                    Kind::All => all_idx = idx,
                    _ => {}
                }
                spf.mechanisms.push(m_str);
                idx = idx + 1;
            }
        }
        if redirect {
            if all_idx > redirect_idx {
                return Err(SpfError::RedirectWithAllMechanism);
            }
            if redirect_idx != idx - 1 {
                return Err(SpfError::RedirectNotFinalMechanism(redirect_idx));
            }
        }
        spf.source = s.to_string();
        spf.redirect_idx = redirect_idx;
        spf.all_idx = all_idx;
        Ok(spf)
    }
}

impl TryFrom<&str> for Spf<String> {
    type Error = SpfError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Spf::from_str(s)
    }
}
impl Spf<String> {
    /// Creates a Spf<String> from the passed str reference.
    /// This is basically a rapper around FromStr which has been implemented for Spf<String>
    /// Creates a `Spf<String>` from the passed str reference.
    /// This is basically a rapper around FromStr which has been implemented for `Spf<String>`
    #[allow(dead_code)]
    pub fn new(s: &str) -> Result<Self, SpfError> {
        s.parse::<Spf<String>>()
    }

    /// Access the version of the Spf String
    pub fn version(&self) -> &str {
        self.version.as_ref()
    }
    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains("v=spf1")
    }
    pub fn redirect(&self) -> Option<&Mechanism<String>> {
        if self.redirect_idx == 0 {
            return match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::Redirect => return self.mechanisms.first(),
                _ => None,
            };
        } else {
            Some(&self.mechanisms[self.redirect_idx as usize])
        }
    }
    pub fn all(&self) -> Option<&Mechanism<String>> {
        if self.all_idx == 0 {
            return match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::All => return self.mechanisms.first(),
                _ => None,
            };
        } else {
            Some(&self.mechanisms[self.all_idx as usize])
        }
    }
    #[allow(dead_code)]
    fn validate(&self) {
        todo!()
    }
}

/// The definition of the Spf struct which contains all information related a single
/// SPF record.
#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpfBuilder {
    source: String,  // Stores original Spf String that was parsed (s.parse())
    version: String, // Version Usually v=spf1 but may be spf2.0/...
    from_src: bool,  // Currently don't know if this is used or what it was used for if not used.
    redirect: Option<Mechanism<String>>,
    is_redirected: bool,
    a: Option<Vec<Mechanism<String>>>,
    mx: Option<Vec<Mechanism<String>>>,
    include: Option<Vec<Mechanism<String>>>,
    ip4: Option<Vec<Mechanism<IpNetwork>>>,
    ip6: Option<Vec<Mechanism<IpNetwork>>>,
    ptr: Option<Mechanism<String>>,
    exists: Option<Vec<Mechanism<String>>>,
    all: Option<Mechanism<String>>,
    was_parsed: bool,
    was_validated: bool,
    is_valid: bool,
}

impl From<Spf<String>> for SpfBuilder {
    fn from(source: Spf<String>) -> Self {
        let mut new_spf = SpfBuilder::new();
        new_spf.version = source.version;
        for m in source.mechanisms.into_iter() {
            new_spf.append_mechanism(m);
        }
        new_spf
    }
}
impl Display for SpfBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_spf_string())
    }
}

impl SpfBuilder {
    /// Create a new empty Spf struct.
    pub fn new() -> Self {
        SpfBuilder::default()
    }
    /// Check that data stored in the Spf Struct is considered a valid Spf Record.
    pub fn is_valid(&self) -> bool {
        if self.was_validated {
            return self.is_valid;
        };
        false
    }
    /// Set version to `v=spf1`
    pub fn set_v1(&mut self) {
        self.version = String::from("v=spf1");
    }
    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains("v=spf1")
    }
    /// Return a reference to version
    pub fn version(&self) -> &String {
        &self.version
    }
    /// Append a Redirect Mechanism to the Spf Struct.
    fn append_mechanism_of_redirect(&mut self, mechanism: Mechanism<String>) {
        self.redirect = Some(mechanism);
        self.is_redirected = true;
        if self.all.is_some() {
            self.all = None;
        }
    }
    /// Clear the passed Kind which has been passed.
    /// Sets the passed mechanism to `None`
    ///
    /// # Note:
    /// This method clears all associated Mechanism for the [`Kind`](Kind) provided.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::{Qualifier, Kind, Mechanism};
    /// use decon_spf::SpfBuilder;
    /// let mut spf = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::all(Qualifier::Pass));
    /// spf.append_mechanism(Mechanism::a(Qualifier::Pass));
    /// spf.append_ip_mechanism(Mechanism::ip(Qualifier::Pass,
    ///                                                  "203.32.160.0/23".parse().unwrap()));
    /// assert_eq!(spf.to_string(), "v=spf1 a ip4:203.32.160.0/23 all".to_string());
    /// // Remove ip4 Mechanism
    /// spf.clear_mechanism(Kind::IpV4);
    /// assert_eq!(spf.to_string(), "v=spf1 a all".to_string());
    ///```
    pub fn clear_mechanism(&mut self, kind: Kind) {
        match kind {
            Kind::Redirect => {
                self.redirect = None;
                self.is_redirected = false;
            }
            Kind::A => self.a = None,
            Kind::MX => self.mx = None,
            Kind::Include => self.include = None,
            Kind::IpV4 => self.ip4 = None,
            Kind::IpV6 => self.ip6 = None,
            Kind::Exists => self.exists = None,
            Kind::Ptr => self.ptr = None,
            Kind::All => self.all = None,
        }
    }

    fn append_mechanism_of_a(&mut self, mechanism: Mechanism<String>) {
        if let Some(a) = &mut self.a {
            a.push(mechanism);
        } else {
            self.a = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_mx(&mut self, mechanism: Mechanism<String>) {
        if let Some(mx) = &mut self.mx {
            mx.push(mechanism);
        } else {
            self.mx = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_include(&mut self, mechanism: Mechanism<String>) {
        if let Some(include) = &mut self.include {
            include.push(mechanism);
        } else {
            self.include = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_ip4(&mut self, mechanism: Mechanism<IpNetwork>) {
        if let Some(ip4) = &mut self.ip4 {
            ip4.push(mechanism);
        } else {
            self.ip4 = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_ip6(&mut self, mechanism: Mechanism<IpNetwork>) {
        if let Some(ip6) = &mut self.ip6 {
            ip6.push(mechanism);
        } else {
            self.ip6 = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_exists(&mut self, mechanism: Mechanism<String>) {
        if let Some(exists) = &mut self.exists {
            exists.push(mechanism);
        } else {
            self.exists = Some(vec![mechanism]);
        }
    }
    fn append_mechanism_of_ptr(&mut self, mechanism: Mechanism<String>) {
        self.ptr = Some(mechanism);
    }
    fn append_mechanism_of_all(&mut self, mechanism: Mechanism<String>) {
        if self.redirect.is_none() {
            self.all = Some(mechanism);
        }
    }
    /// Appends the passed `Mechanism<String>` to the SPF struct.
    /// This only works for Mechanism which are *NOT* `ip4:` or `ip6:`
    ///
    /// # Example:
    /// ```
    /// use decon_spf::{Qualifier, Mechanism};
    /// use decon_spf::SpfBuilder;
    /// let mut spf = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::redirect(Qualifier::Pass,
    ///                                 "_spf.example.com").unwrap());
    /// spf.append_mechanism(Mechanism::all(Qualifier::Pass));
    /// assert_eq!(spf.to_string(), "v=spf1 redirect=_spf.example.com".to_string());
    /// ```
    ///
    /// # Note:
    /// If the Spf is already set as `Redirect` trying to append an `All`
    /// Mechanism will have no affect.
    // Consider make this a Result
    pub fn append_mechanism(&mut self, mechanism: Mechanism<String>) {
        match mechanism.kind() {
            Kind::Redirect => self.append_mechanism_of_redirect(mechanism),
            Kind::A => self.append_mechanism_of_a(mechanism),
            Kind::MX => self.append_mechanism_of_mx(mechanism),
            Kind::Include => self.append_mechanism_of_include(mechanism),
            Kind::Exists => self.append_mechanism_of_exists(mechanism),
            Kind::Ptr => self.append_mechanism_of_ptr(mechanism),
            Kind::All => self.append_mechanism_of_all(mechanism),
            _ => {}
        }
    }
    /// Appends the passed `Mechanism<IpNetwork>` to the SPF struct.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::{Qualifier, Mechanism};
    /// use decon_spf::SpfBuilder;
    /// let mut spf = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_ip_mechanism(Mechanism::ip(Qualifier::Pass,
    ///                                 "203.32.160.0/23".parse().unwrap()));
    /// spf.append_mechanism(Mechanism::all(Qualifier::Pass));
    /// assert_eq!(spf.to_string(), "v=spf1 ip4:203.32.160.0/23 all".to_string());
    /// ```    
    pub fn append_ip_mechanism(&mut self, mechanism: Mechanism<IpNetwork>) {
        match mechanism.kind() {
            Kind::IpV4 => self.append_mechanism_of_ip4(mechanism),
            Kind::IpV6 => self.append_mechanism_of_ip6(mechanism),
            _ => {
                unreachable!()
            }
        }
    }
    #[allow(dead_code)]
    fn validate(&mut self, rfc: SpfRfcStandard) -> Result<&Self, SpfError> {
        return match rfc {
            SpfRfcStandard::Rfc4408 => validate::validate_rfc4408(self),
        };
    }
    #[allow(dead_code)]
    fn validate_to_string(&mut self, rfc: SpfRfcStandard) -> SpfValidationResult {
        let res = match rfc {
            SpfRfcStandard::Rfc4408 => validate::validate_rfc4408(self),
        };
        match res {
            Ok(x) => SpfValidationResult::Valid(x),
            Err(x) => SpfValidationResult::InValid(x),
        }
    }

    fn build_spf_string(&self) -> String {
        let mut spf = String::new();
        spf.push_str(self.version());
        if let Some(a) = self.a() {
            spf.push_str(core::build_spf_str(a).as_str());
        };
        if let Some(mx) = self.mx() {
            spf.push_str(core::build_spf_str(mx).as_str());
        };
        if let Some(includes) = self.includes() {
            spf.push_str(core::build_spf_str(includes).as_str());
        }
        if let Some(ip4) = self.ip4() {
            spf.push_str(core::build_spf_str_from_ip(ip4).as_str());
        }
        if let Some(ip6) = self.ip6() {
            spf.push_str(core::build_spf_str_from_ip(ip6).as_str());
        }
        if let Some(exists) = self.exists() {
            spf.push_str(core::build_spf_str(exists).as_str());
        }
        if let Some(ptr) = self.ptr() {
            spf.push(' ');
            spf.push_str(ptr.to_string().as_str());
        }
        if self.is_redirected {
            spf.push(' ');
            spf.push_str(self.redirect().unwrap().to_string().as_str());
        }
        // All can only be used if this is not a redirect.
        if !self.is_redirected && self.all().is_some() {
            spf.push(' ');
            spf.push_str(self.all().unwrap().to_string().as_str());
        }
        spf
    }
    /// Returns a reference to the string stored in `source`
    pub fn source(&self) -> &String {
        // Source is set to "" by default.
        &self.source
    }
    /// True if there is a redirect present in the spf record.
    pub fn is_redirect(&self) -> bool {
        self.is_redirected
    }
    /// Returns a reference to the `Redirect` Mechanism
    pub fn redirect(&self) -> Option<&Mechanism<String>> {
        self.redirect.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<String>` for `Include`
    pub fn includes(&self) -> Option<&Vec<Mechanism<String>>> {
        self.include.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<String>` for `A`
    pub fn a(&self) -> Option<&Vec<Mechanism<String>>> {
        self.a.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<String>` for `MX`
    pub fn mx(&self) -> Option<&Vec<Mechanism<String>>> {
        self.mx.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<IpNetwork>` for `IP4`
    pub fn ip4(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip4.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<IpNetwork>` for `IP6`
    pub fn ip6(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip6.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<String>` for `Exists`
    pub fn exists(&self) -> Option<&Vec<Mechanism<String>>> {
        self.exists.as_ref()
    }
    /// Returns a reference to a `Vec` of `Mechanism<String>` for `Ptr`
    pub fn ptr(&self) -> Option<&Mechanism<String>> {
        self.ptr.as_ref()
    }
    /// Returns a reference to `Mechanism<String>` for `All`
    pub fn all(&self) -> Option<&Mechanism<String>> {
        self.all.as_ref()
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "spf2")))]
#[cfg(feature = "spf2")]
impl SpfBuilder {
    /// Set version to `spf2.0/pra`
    pub fn set_v2_pra(&mut self) {
        self.version = String::from("spf2.0/pra");
    }
    /// Set version to `spf2.0/mfrom`
    pub fn set_v2_mfrom(&mut self) {
        self.version = String::from("spf2.0/mfrom");
    }
    /// Set version to `spf2.0/pra,mfrom`
    pub fn set_v2_pra_mfrom(&mut self) {
        self.version = String::from("spf2.0/pra,mfrom");
    }
    /// Set version to `spf2.0/mfrom,pra`
    pub fn set_v2_mfrom_pra(&mut self) {
        self.version = String::from("spf2.0/mfrom,pra");
    }
    /// Check that version is v2
    pub fn is_v2(&self) -> bool {
        self.version.starts_with("spf2.0/pra") || self.version.starts_with("spf2.0/mfrom")
    }
}
