use crate::core::{DNS_LOOKUP_LIMIT, SPF1, SPF2};
use crate::spf::mechanism::{builder::All, Kind, Mechanism, MechanismError};
use crate::spf::validate::{self, Validate};
use crate::{Spf, SpfError};
use ipnetwork::IpNetwork;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct Builder;
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed;

#[derive(Debug, Clone, PartialEq)]
pub struct Redirected;

#[derive(Debug, Clone, PartialEq)]
pub struct ContainsAll;

/// The definition of the SpfBuilder struct which contains all information related a single
/// SPF record.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpfBuilder<State = Builder> {
    // Version is usually v=spf1 but may be spf2.0/...
    version: String,
    redirect: Option<Mechanism<String>>,
    a: Option<Vec<Mechanism<String>>>,
    mx: Option<Vec<Mechanism<String>>>,
    include: Option<Vec<Mechanism<String>>>,
    ip4: Option<Vec<Mechanism<IpNetwork>>>,
    ip6: Option<Vec<Mechanism<IpNetwork>>>,
    ptr: Option<Mechanism<String>>,
    exists: Option<Vec<Mechanism<String>>>,
    all: Option<Mechanism<All>>,
    #[cfg_attr(feature = "serde", serde(skip))]
    state: PhantomData<State>,
}

pub trait Modifiable {}

impl Modifiable for Builder {}
impl Modifiable for Redirected {}
impl Modifiable for ContainsAll {}
impl Modifiable for SpfBuilder {}

pub trait Buildable {}
impl Buildable for Builder {}
impl Buildable for Parsed {}
impl<State> Default for SpfBuilder<State> {
    fn default() -> Self {
        Self {
            version: "".to_string(),
            redirect: None,
            a: None,
            mx: None,
            include: None,
            ip4: None,
            ip6: None,
            ptr: None,
            exists: None,
            all: None,
            is_valid: false,
            state: Default::default(),
        }
    }
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

/// Converts a `Spf<String> into a `SpfBuilder`struct.
impl From<Spf<String>> for SpfBuilder<Builder> {
    fn from(source: Spf<String>) -> SpfBuilder<Builder> {
        build_spf(source)
    }
}
#[cfg(test)]
mod string_to_builder {
    use super::*;

    #[test]
    fn from_string_to_builder() {
        let spf = "v=spf1 a mx -all".parse::<Spf<String>>().unwrap();
        let builder = SpfBuilder::<Builder>::from(spf);
        assert_eq!(builder.version, "v=spf1");
        assert!(builder.mx().is_some());
        assert!(builder.redirect().is_none());
    }
    #[test]
    fn from_string_to_builder_ip() {
        let spf = "v=spf1 mx ip4:203.32.160.10 -all"
            .parse::<Spf<String>>()
            .unwrap();
        let builder: SpfBuilder<Builder> = SpfBuilder::from(spf);
        assert_eq!(builder.version, "v=spf1");
        assert!(builder.mx.is_some());
        assert!(builder.ip4.is_some());
        assert!(builder.a().is_none());
    }
}

impl<State> Display for SpfBuilder<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.build_spf_string())
    }
}

/// Creates an `SpfBuilder struct` by parsing a string representation of Spf.
///
/// # Examples:
///
///```rust
/// use decon_spf::{Parsed, SpfBuilder};
/// use decon_spf::SpfError;
/// // Successful
/// let input = "v=spf1 a mx -all";
/// let spf: SpfBuilder<Parsed> = input.parse::<SpfBuilder<_>>().unwrap();
/// assert_eq!(spf.to_string(), input);
///
/// // Additional Space between `A` and `MX`
/// let invalid_input = "v=spf1 a   mx -all";
/// let err: SpfError = invalid_input.parse::<SpfBuilder<_>>().unwrap_err();
/// assert_eq!(err, SpfError::WhiteSpaceSyntaxError);
/// //  err.to_string() -> "Spf contains two or more consecutive whitespace characters.");
///```
///
impl FromStr for SpfBuilder<Parsed> {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;
        // Consider making this a soft Error similar to Spf<String>
        validate::check_whitespaces(s)?;
        let source = String::from(s);

        // Basic Checks are ok.
        let mut spf = SpfBuilder::new();
        // Setup Vectors
        let records = source.split_whitespace();

        for record in records {
            // Consider ensuring we do this once at least and then skip
            if record.contains(SPF1) || record.starts_with(SPF2) {
                spf.version = record.to_string();
            } else if record.contains(crate::core::REDIRECT) {
                if spf.redirect.is_some() {
                    return Err(SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
                }
                let m: Mechanism<String> = record.parse()?;
                spf.redirect = Some(m);
            } else if record.contains(crate::core::INCLUDE) {
                let m: Mechanism<String> = record.parse()?;
                spf.append_string_mechanism(m);
            } else if record.contains(crate::core::IP4) || record.contains(crate::core::IP6) {
                let m = record.parse::<Mechanism<IpNetwork>>()?;
                spf.append_ip_mechanism(m);
            } else if record.ends_with(crate::core::ALL) && (record.len() == 3 || record.len() == 4)
            {
                spf.all = Some(Mechanism::all_with_qualifier(
                    crate::core::return_and_remove_qualifier(record, 'a').0,
                ));
                // Handle A, MX, Exists and PTR types.
            } else if let Ok(a_mechanism) = crate::core::spf_regex::capture_matches(record, Kind::A)
            {
                spf.append_string_mechanism(a_mechanism);
            } else if let Ok(mx_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::MX)
            {
                spf.append_string_mechanism(mx_mechanism);
            } else if let Ok(ptr_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::Ptr)
            {
                if spf.ptr.is_some() {
                    return Err(SpfError::ModifierMayOccurOnlyOnce(Kind::Ptr));
                }
                spf.ptr = Some(ptr_mechanism);
            } else if let Ok(exists_mechanism) =
                crate::core::spf_regex::capture_matches(record, Kind::Exists)
            {
                spf.append_string_mechanism(exists_mechanism);
            } else {
                return Err(SpfError::InvalidMechanism(
                    MechanismError::InvalidMechanismFormat(record.to_string()),
                ));
            }
        }
        Ok(spf)
    }
}

impl<State> SpfBuilder<State> {
    /// Create a new empty SpfBuilder struct.
    pub fn new() -> Self {
        SpfBuilder::default()
    }
    /// Access the version attribute
    pub fn version(&self) -> &String {
        &self.version
    }
}
impl SpfBuilder<Builder> {
    pub fn new_builder() -> SpfBuilder<Builder> {
        SpfBuilder {
            state: PhantomData::<Builder>,
            ..Default::default()
        }
    }
}
impl SpfBuilder<Parsed> {
    pub fn new_parsed() -> SpfBuilder<Parsed> {
        SpfBuilder {
            state: PhantomData::<Parsed>,
            ..Default::default()
        }
    }
}

impl SpfBuilder<Builder> {
    /// Set version to `v=spf1`
    pub fn set_v1(&mut self) -> &mut Self {
        self.version = String::from(SPF1);
        self
    }
    pub fn add_a(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.append_mechanism(mechanism)
    }
    pub fn add_mx(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.append_mechanism(mechanism)
    }
    pub fn add_include(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.append_mechanism(mechanism)
    }
    pub fn add_ip(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        self.append_mechanism(mechanism)
    }
    /// Append a Redirect Mechanism to the Spf Struct.
    pub fn add_redirect(mut self, mechanism: Mechanism<String>) -> SpfBuilder<Redirected> {
        SpfBuilder {
            version: self.version.to_owned(),
            redirect: Some(mechanism),
            a: self.a.take(),
            mx: self.mx.take(),
            include: self.include.take(),
            ip4: self.ip4.take(),
            ip6: self.ip6.take(),
            ptr: self.ptr.take(),
            exists: self.exists.take(),
            all: self.all.take(),
            is_valid: false,
            state: PhantomData::<Redirected>,
        }
    }
    pub fn add_all(mut self, mechanism: Mechanism<All>) -> SpfBuilder<ContainsAll> {
        SpfBuilder {
            version: self.version.to_owned(),
            redirect: self.redirect.take(),
            a: self.a.take(),
            mx: self.mx.take(),
            include: self.include.take(),
            ip4: self.ip4.take(),
            ip6: self.ip6.take(),
            ptr: self.ptr.take(),
            exists: self.exists.take(),
            all: Some(mechanism),
            is_valid: false,
            state: PhantomData::<ContainsAll>,
        }
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "spf2")))]
#[cfg(feature = "spf2")]
impl<State: Modifiable> SpfBuilder<State> {
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
impl<State> SpfBuilder<State> {
    /// Clear the passed Kind which has been passed.
    /// Sets the passed mechanism to `None`
    ///
    /// # Note:
    /// This method clears all associated Mechanism for the [`Kind`] provided.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::{Qualifier, Kind, Mechanism};
    /// use decon_spf::{Builder, SpfBuilder};
    /// let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
    /// spf.append_mechanism(Mechanism::a(Qualifier::Pass));
    /// spf.append_mechanism(Mechanism::ip(Qualifier::Pass,
    ///                                                  "203.32.160.0/23".parse().unwrap()));
    /// // Remove ip4 Mechanism
    /// spf.clear_mechanism(Kind::IpV4);
    ///```
    pub fn clear_mechanism(&mut self, kind: Kind)
    where
        State: Modifiable,
    {
        match kind {
            Kind::Redirect => self.redirect = None,
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

    pub(crate) fn append_mechanism_of_redirect(
        &mut self,
        mechanism: Mechanism<String>,
    ) -> &mut Self {
        self.redirect = Some(mechanism);
        self
    }
    pub(crate) fn append_mechanism_of_a(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(m_vec) = &mut self.a {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.a = Some(vec![mechanism]);
        }
        self
    }

    // Before add a Mechanism to its Vec we check to make sure the same Mechanism does not already
    // exist. If it exists it is not appended to avoid duplication.
    fn check_mechanism_in_vec<T>(mechanism: &Mechanism<T>, m_vec: &Vec<Mechanism<T>>) -> bool
    where
        T: PartialEq,
    {
        let mut exists = false;
        for m in m_vec.iter() {
            exists = m == mechanism;
        }
        exists
    }

    pub(crate) fn append_mechanism_of_mx(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(m_vec) = &mut self.mx {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.mx = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_include(
        &mut self,
        mechanism: Mechanism<String>,
    ) -> &mut Self {
        if let Some(m_vec) = &mut self.include {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.include = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_ip4(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        if let Some(m_vec) = &mut self.ip4 {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.ip4 = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_ip6(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        if let Some(m_vec) = &mut self.ip6 {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.ip6 = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_exists(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        if let Some(m_vec) = &mut self.exists {
            let exists = Self::check_mechanism_in_vec(&mechanism, m_vec);
            if !exists {
                m_vec.push(mechanism);
            }
        } else {
            self.exists = Some(vec![mechanism]);
        }
        self
    }
    pub(crate) fn append_mechanism_of_ptr(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.ptr = Some(mechanism);
        self
    }
    pub(crate) fn append_mechanism_of_all(&mut self, mechanism: Mechanism<All>) -> &mut Self {
        self.all = Some(mechanism);
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
    /// use decon_spf::{Builder, SpfBuilder};
    /// let mut spf: SpfBuilder<Builder> = SpfBuilder::new();
    /// spf.set_v1();
    /// spf.append_mechanism(Mechanism::redirect(Qualifier::Pass,
    ///                                 "_spf.example.com").unwrap())
    ///    .append_mechanism(Mechanism::all_with_qualifier(Qualifier::Pass));
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
        if self.redirect.is_some() {
            spf.push(' ');
            spf.push_str(
                self.redirect()
                    .expect("Should not fail")
                    .to_string()
                    .as_str(),
            );
        }
        // All can only be used if this is not a redirect.
        if self.redirect.is_none() && self.all().is_some() {
            spf.push(' ');
            spf.push_str(self.all().expect("Should not fail.").to_string().as_str());
        }
        spf
    }
    /// True if there is a redirect present in the spf record.
    pub fn is_redirect(&self) -> bool {
        self.redirect.is_some()
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
    pub fn build(mut self) -> Result<Spf<String>, SpfError>
    where
        State: Buildable,
    {
        if self.version.is_empty() {
            self.version = SPF1.to_owned();
        }
        self.validate_lookup_count()?;
        self.validate_ptr()?;
        self.validate_redirect_all()?;
        let lookup_count: u8 = self.get_lookup_count() as u8;

        let mut redirect_idx = 0;
        let mut has_redirect = false;
        let mut all_idx = 0;
        let mut mechanisms: Vec<Mechanism<String>> = Vec::with_capacity(DNS_LOOKUP_LIMIT + 1); // +1 for Version information

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
            has_redirect = true;
            redirect_idx = mechanisms.len() - 1;
        }
        Ok(Spf::<String> {
            source: "".to_string(),
            version: self.version,
            redirect_idx,
            has_redirect,
            all_idx,
            lookup_count,
            mechanisms,
        })
    }

    pub(crate) fn get_lookup_count(&self) -> usize {
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

impl<State> SpfBuilder<State> {
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
impl<State> Append<String> for SpfBuilder<State> {
    fn append(&mut self, mechanism: Mechanism<String>) -> &mut Self {
        self.append_string_mechanism(mechanism)
    }
}

impl<State> Append<IpNetwork> for SpfBuilder<State> {
    fn append(&mut self, mechanism: Mechanism<IpNetwork>) -> &mut Self {
        self.append_ip_mechanism(mechanism)
    }
}

impl<State> Append<All> for SpfBuilder<State> {
    fn append(&mut self, mechanism: Mechanism<All>) -> &mut Self {
        self.append_mechanism_of_all(mechanism)
    }
}

#[test]
fn spf_builder_iter() {
    use crate::spf::mechanism::Qualifier;
    let mut spf_b: SpfBuilder<Builder> = SpfBuilder::new();
    let mut count = 0;
    spf_b
        //.append(Mechanism::redirect(Qualifier::Pass, "example.com").unwrap())
        .append(Mechanism::a(Qualifier::Pass))
        .append(Mechanism::ip_from_string("ip4:203.160.10.10").unwrap())
        .append(Mechanism::ip_from_string("ip6:2001:4860:4000::").unwrap())
        .append(Mechanism::include(Qualifier::Pass, "test.com").unwrap())
        .append(Mechanism::all_default());
    for _m in spf_b.iter() {
        count += 1;
    }
    assert_eq!(count, 5);
}

fn build_spf<T>(source: Spf<String>) -> SpfBuilder<T> {
    let mut new_spf = SpfBuilder::new();
    new_spf.version = source.version;

    for m in source.mechanisms.into_iter() {
        match m.kind() {
            Kind::IpV4 | Kind::IpV6 => {
                let ip_m = Mechanism::ip_from_string(&*m.to_string())
                    .expect("Mechanism is not a valid IP address. Should never happen");
                new_spf.append_mechanism(ip_m);
            }
            Kind::All => {
                new_spf.all = Some(
                    m.try_into()
                        .expect("Not All Mechanisms. Should never happen."),
                );
            }
            Kind::Redirect => {
                new_spf.redirect = Some(m);
            }
            _ => {
                new_spf.append_mechanism(m);
            }
        }
    }

    new_spf
}
