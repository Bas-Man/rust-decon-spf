use crate::spf::mechanism::{All, Kind, Mechanism, MechanismError};
use crate::spf::validate::{self, SpfRfcStandard, SpfValidationResult};
use crate::{Spf, SpfError};
use ipnetwork::IpNetwork;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// The definition of the SpfBuilder struct which contains all information related a single
/// SPF record.
#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpfBuilder {
    version: String,
    // Version is usually v=spf1 but may be spf2.0/...
    redirect: Option<Mechanism<String>>,
    is_redirected: bool,
    a: Option<Vec<Mechanism<String>>>,
    mx: Option<Vec<Mechanism<String>>>,
    include: Option<Vec<Mechanism<String>>>,
    ip4: Option<Vec<Mechanism<IpNetwork>>>,
    ip6: Option<Vec<Mechanism<IpNetwork>>>,
    pub(crate) ptr: Option<Mechanism<String>>,
    exists: Option<Vec<Mechanism<String>>>,
    all: Option<Mechanism<All>>,
    pub(crate) is_valid: bool,
}

pub struct SpfBuilderIterator {
    m_iter: std::vec::IntoIter<Mechanism<String>>,
}

impl Iterator for SpfBuilderIterator {
    type Item = Mechanism<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.m_iter.next()
    }
}

impl From<Spf<String>> for SpfBuilder {
    fn from(source: Spf<String>) -> Self {
        let mut new_spf = SpfBuilder::new();
        new_spf.version = source.version;
        for m in source.mechanisms.into_iter() {
            new_spf.append_string_mechanism(m);
        }
        new_spf
    }
}

impl Display for SpfBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_spf_string())
    }
}

/// Creates an `SpfBuilder struct` by parsing a string representation of Spf.
///
/// # Examples:
///
///```rust
/// use decon_spf::SpfBuilder;
/// use decon_spf::SpfError;
/// // Successful
/// let input = "v=spf1 a mx -all";
/// let spf: SpfBuilder = input.parse().unwrap();
/// assert_eq!(spf.to_string(), input);
///
/// // Additional Space between `A` and `MX`
/// let invalid_input = "v=spf1 a   mx -all";
/// let err: SpfError =invalid_input.parse::<SpfBuilder>().unwrap_err();
/// assert_eq!(err, SpfError::WhiteSpaceSyntaxError);
/// //  err.to_string() -> "Spf contains two or more consecutive whitespace characters.");
///```
///
impl FromStr for SpfBuilder {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;
        validate::check_whitespaces(s)?;
        let source = String::from(s);

        // Basic Checks are ok.
        let mut spf = SpfBuilder::new();
        // Setup Vectors
        let records = source.split_whitespace();
        let mut vec_of_includes: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_ip4: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_ip6: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_a: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_mx: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_exists: Vec<Mechanism<String>> = Vec::new();

        for record in records {
            // Consider ensuring we do this once at least and then skip
            if record.contains(crate::core::SPF1) || record.starts_with("spf2.0") {
                spf.version = record.to_string();
            } else if record.contains("redirect=") {
                let m: Mechanism<String> = record.parse()?;
                spf.redirect = Some(m);
                spf.is_redirected = true;
            } else if record.contains("include:") {
                let m: Mechanism<String> = record.parse()?;
                vec_of_includes.push(m);
            } else if record.contains(crate::core::IP4) || record.contains(crate::core::IP6) {
                let m = record.parse::<Mechanism<IpNetwork>>()?;
                match m.kind() {
                    Kind::IpV4 => vec_of_ip4.push(m),
                    Kind::IpV6 => vec_of_ip6.push(m),
                    _ => unreachable!(),
                }
            } else if record.ends_with("all") && (record.len() == 3 || record.len() == 4) {
                spf.all = Some(Mechanism::all_with_qualifier(
                    crate::core::return_and_remove_qualifier(record, 'a').0,
                ));
                // Handle A, MX, Exists and PTR types.
            } else if let Ok(a_mechanism) = crate::core::spf_regex::capture_matches(record, Kind::A)
            {
                vec_of_a.push(a_mechanism);
            } else if let Ok(mx_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::MX)
            {
                vec_of_mx.push(mx_mechanism);
            } else if let Ok(ptr_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::Ptr)
            {
                spf.ptr = Some(ptr_mechanism);
            } else if let Ok(exists_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::Exists)
            {
                vec_of_exists.push(exists_mechanism);
            } else {
                return Err(SpfError::InvalidMechanism(
                    MechanismError::InvalidMechanismFormat(record.to_string()),
                ));
            }
        }
        // Move vec_of_* into the SpfBuilder struct
        if !vec_of_includes.is_empty() {
            spf.include = Some(vec_of_includes);
        };
        if !vec_of_ip4.is_empty() {
            spf.ip4 = Some(vec_of_ip4);
        };
        if !vec_of_ip6.is_empty() {
            spf.ip6 = Some(vec_of_ip6);
        };
        if !vec_of_a.is_empty() {
            spf.a = Some(vec_of_a);
        }
        if !vec_of_mx.is_empty() {
            spf.mx = Some(vec_of_mx);
        }
        if !vec_of_exists.is_empty() {
            spf.exists = Some(vec_of_exists);
        }

        Ok(spf)
    }
}

impl SpfBuilder {
    /// Create a new empty SpfBuilder struct.
    pub fn new() -> Self {
        SpfBuilder::default()
    }
    /// Set version to `v=spf1`
    pub fn set_v1(&mut self) -> &mut Self {
        self.version = String::from(crate::core::SPF1);
        self
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "spf2")))]
#[cfg(feature = "spf2")]
impl SpfBuilder {
    /// Set version to `spf2.0/pra`
    pub fn set_v2_pra(&mut self) -> &mut Self {
        self.version = String::from(crate::core::SPF2_PRA);
        self
    }
    /// Set version to `spf2.0/mfrom`
    pub fn set_v2_mfrom(&mut self) -> &mut Self {
        self.version = String::from(crate::core::SPF2_MFROM);
        self
    }
    /// Set version to `spf2.0/pra,mfrom`
    pub fn set_v2_pra_mfrom(&mut self) -> &mut Self {
        self.version = String::from(crate::core::SPF2_PRA_MFROM);
        self
    }
    /// Set version to `spf2.0/mfrom,pra`
    pub fn set_v2_mfrom_pra(&mut self) -> &mut Self {
        self.version = String::from(crate::core::SPF2_MFROM_PRA);
        self
    }
    /// Check that version is v2
    pub fn is_v2(&self) -> bool {
        self.version.starts_with(crate::core::SPF2_PRA)
            || self.version.starts_with(crate::core::SPF2_MFROM)
    }
}

impl SpfBuilder {
    /// Access the version attribute
    pub fn version(&self) -> &String {
        &self.version
    }
    /// Append a Redirect Mechanism to the Spf Struct.
    fn append_mechanism_of_redirect(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.redirect = Some(mechanism);
        // # todo This line is not needed.
        if !self.is_redirected {}
        self.is_redirected = true;
        if self.all.is_some() {
            self.all = None;
        }
        self
    }
    /// Clear the passed Kind which has been passed.
    /// Sets the passed mechanism to `None`
    ///
    /// # Note:
    /// This method clears all associated Mechanism for the [`Kind`] provided.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::{Qualifier, Kind, Mechanism};
    /// use decon_spf::SpfBuilder;
    /// let mut spf = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
    /// spf.append_mechanism(Mechanism::a(Qualifier::Pass));
    /// spf.append_mechanism(Mechanism::ip(Qualifier::Pass,
    ///                                                  "203.32.160.0/23".parse().unwrap()));
    /// // Remove ip4 Mechanism
    /// spf.clear_mechanism(Kind::IpV4);
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

    pub(crate) fn append_mechanism_of_a(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(a) = &mut self.a {
            a.push(mechanism);
        } else {
            self.a = Some(vec![mechanism]);
        }
        self
    }
    fn append_mechanism_of_mx(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(mx) = &mut self.mx {
            mx.push(mechanism);
        } else {
            self.mx = Some(vec![mechanism]);
        }
        self
    }
    fn append_mechanism_of_include(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(include) = &mut self.include {
            include.push(mechanism);
        } else {
            self.include = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_ip4(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        if let Some(ip4) = &mut self.ip4 {
            ip4.push(mechanism);
        } else {
            self.ip4 = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_ip6(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        if let Some(ip6) = &mut self.ip6 {
            ip6.push(mechanism);
        } else {
            self.ip6 = Some(vec![mechanism]);
        }
        self
    }
    fn append_mechanism_of_exists(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(exists) = &mut self.exists {
            exists.push(mechanism);
        } else {
            self.exists = Some(vec![mechanism]);
        }
        self
    }
    fn append_mechanism_of_ptr(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.ptr = Some(mechanism);
        self
    }
    pub(crate) fn append_mechanism_of_all(&mut self, mechanism: Mechanism<All>) -> &mut Self {
        if self.redirect.is_none() {
            self.all = Some(mechanism);
        }
        self
    }
    pub(crate) fn append_string_mechanism(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        match mechanism.kind() {
            Kind::Redirect => self.append_mechanism_of_redirect(mechanism),
            Kind::A => self.append_mechanism_of_a(mechanism),
            Kind::MX => self.append_mechanism_of_mx(mechanism),
            Kind::Include => self.append_mechanism_of_include(mechanism),
            Kind::Exists => self.append_mechanism_of_exists(mechanism),
            Kind::Ptr => self.append_mechanism_of_ptr(mechanism),
            Kind::All => {
                self.append_mechanism_of_all(mechanism.try_into().expect("Not a Mechanism<All>"))
            }
            _ => {
                panic!("What the heck? Unmatched case?")
            }
        }
    }
    pub(crate) fn append_ip_mechanism(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        match mechanism.kind() {
            Kind::IpV4 => self.append_mechanism_of_ip4(mechanism),
            Kind::IpV6 => self.append_mechanism_of_ip6(mechanism),
            _ => {
                unreachable!()
            }
        }
    }
    /// ```
    /// use decon_spf::mechanism::{Qualifier, Mechanism};
    /// use decon_spf::SpfBuilder;
    /// let mut spf = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::redirect(Qualifier::Pass,
    ///                                 "_spf.example.com").unwrap())
    ///    .append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
    /// assert!(spf.all().is_none());
    /// ```
    /// # Note
    /// When Redirect is present, All will be set to None.
    ///
    pub fn append_mechanism<T>(&mut self, mechanism: Mechanism<T>) -> &mut Self
    where
        Self: Append<T>,
    {
        self.append(mechanism);
        self
    }
    #[allow(dead_code)]
    pub(crate) fn validate(&mut self, rfc: SpfRfcStandard) -> Result<&Self, SpfError> {
        match rfc {
            SpfRfcStandard::Rfc4408 => validate::validate_rfc4408(self),
        }
    }
    #[allow(dead_code)]
    pub(crate) fn validate_to_string(&mut self, rfc: SpfRfcStandard) -> SpfValidationResult {
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
            spf.push_str(crate::core::build_spf_str(a).as_str());
        };
        if let Some(mx) = self.mx() {
            spf.push_str(crate::core::build_spf_str(mx).as_str());
        };
        if let Some(includes) = self.includes() {
            spf.push_str(crate::core::build_spf_str(includes).as_str());
        }
        if let Some(ip4) = self.ip4() {
            spf.push_str(crate::core::build_spf_str_from_ip(ip4).as_str());
        }
        if let Some(ip6) = self.ip6() {
            spf.push_str(crate::core::build_spf_str_from_ip(ip6).as_str());
        }
        if let Some(exists) = self.exists() {
            spf.push_str(crate::core::build_spf_str(exists).as_str());
        }
        if let Some(ptr) = self.ptr() {
            spf.push(' ');
            spf.push_str(ptr.to_string().as_str());
        }
        if self.is_redirected {
            spf.push(' ');
            spf.push_str(
                self.redirect()
                    .expect("Should not fail")
                    .to_string()
                    .as_str(),
            );
        }
        // All can only be used if this is not a redirect.
        if !self.is_redirected && self.all().is_some() {
            spf.push(' ');
            spf.push_str(self.all().expect("Should not fail.").to_string().as_str());
        }
        spf
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
    /// Returns a reference to `Mechanism<All>` for `All`
    pub fn all(&self) -> Option<&Mechanism<All>> {
        self.all.as_ref()
    }
    /// Creates a `Spf<String>` from `SpfBuilder`
    // #todo This should probably require that a validation has been completed first.
    pub fn build(mut self) -> Result<Spf<String>, SpfError> {
        if self.version.is_empty() {
            self.set_v1();
        }
        if self.get_lookup_count() > 10 {
            return Err(SpfError::LookupLimitExceeded);
        }
        let mut redirect_idx = 0;
        let mut all_idx = 0;
        let mut mechanisms: Vec<Mechanism<String>> = Vec::with_capacity(10);

        if let Some(list) = self.a.as_mut() {
            mechanisms.append(list);
        }
        if let Some(list) = self.mx.as_mut() {
            mechanisms.append(list);
        }
        if let Some(ip4) = self.ip4 {
            for m in ip4.into_iter() {
                mechanisms.push(m.into());
            }
        }
        if let Some(ip6) = self.ip6 {
            for m in ip6.into_iter() {
                mechanisms.push(m.into());
            }
        }
        if let Some(list) = self.include.as_mut() {
            mechanisms.append(list);
        }
        if let Some(list) = self.exists.as_mut() {
            mechanisms.append(list);
        }
        if let Some(all) = self.all {
            mechanisms.push(all.into());
            all_idx = mechanisms.len() - 1;
        }
        if let Some(redirect) = self.redirect {
            mechanisms.push(redirect);
            redirect_idx = mechanisms.len() - 1;
        }
        Ok(Spf::<String> {
            source: "".to_string(),
            version: self.version,
            redirect_idx,
            all_idx,
            mechanisms,
        })
    }

    fn get_lookup_count(&self) -> usize {
        let mut count: usize = 0;
        {
            if let Some(a) = &self.a {
                count += a.len();
            }
            if let Some(mx) = &self.mx {
                count += mx.len();
            }
            if self.redirect.is_some() {
                count += 1;
            }
            if let Some(exists) = &self.exists {
                count += exists.len();
            }
            if self.ptr.is_some() {
                count += 1;
            }
            if let Some(include) = &self.include {
                count += include.len();
            }
        }
        count
    }
}

impl SpfBuilder {
    /// Allows you to iterate over Mechanisms contained within the SPF record.
    /// # Note: Version string is not included.
    pub fn iter(&self) -> SpfBuilderIterator {
        let mut m: Vec<Mechanism<String>> = vec![];

        if let Some(r) = &self.redirect {
            m.push(r.clone());
        }

        if let Some(m_a) = &self.a {
            m.extend(m_a.iter().cloned())
        }
        if let Some(m_mx) = &self.mx {
            m.extend(m_mx.iter().cloned())
        }
        if let Some(include) = &self.include {
            m.extend(include.iter().cloned())
        }
        if let Some(ip4) = &self.ip4 {
            m.extend(ip4.iter().map(|v| (*v).into()))
        }
        if let Some(ip6) = &self.ip6 {
            m.extend(ip6.iter().map(|v| (*v).into()))
        }
        if let Some(exists) = &self.exists {
            m.extend(exists.iter().cloned())
        }
        if let Some(ptr) = &self.ptr {
            m.push(ptr.clone())
        }
        if let Some(all) = &self.all {
            m.push((*all).clone().into())
        }

        SpfBuilderIterator {
            m_iter: m.into_iter(),
        }
    }
}

pub trait Append<T> {
    fn append(&mut self, mechanism: Mechanism<T>) -> &mut Self;
}
impl Append<String> for SpfBuilder {
    fn append(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.append_string_mechanism(mechanism)
    }
}

impl Append<IpNetwork> for SpfBuilder {
    fn append(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        self.append_ip_mechanism(mechanism)
    }
}

impl Append<All> for SpfBuilder {
    fn append(&mut self, mechanism: Mechanism<All>) -> &mut Self {
        self.append_mechanism_of_all(mechanism)
    }
}

#[test]
fn spf_builder_iter() {
    use crate::spf::mechanism::Qualifier;
    let mut spf_b = SpfBuilder::new();
    spf_b
        //.append(Mechanism::redirect(Qualifier::Pass, "example.com").unwrap())
        .append(Mechanism::a(Qualifier::Pass))
        .append(Mechanism::ip_from_string("ip4:203.160.10.10").unwrap())
        .append(Mechanism::ip_from_string("ip6:2001:4860:4000::").unwrap())
        .append(Mechanism::include(Qualifier::Pass, "test.com").unwrap())
        .append(Mechanism::all_default());
}
