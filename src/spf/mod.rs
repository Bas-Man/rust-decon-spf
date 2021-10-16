//! This module allows you to deconstruct an exiting SPF DNS Record into its
//! constituent parts.  
//! It is not intended to validate the spf record.

mod tests;

use crate::helpers;
use crate::mechanism::Mechanism;
use crate::mechanism::MechanismKind;
use crate::mechanism::Qualifier;
use ipnetwork::IpNetwork;
use ipnetwork::IpNetworkError;

/// A list of expected possible errors for SPF records.
#[derive(Debug, PartialEq)]
pub enum SpfErrorType {
    /// Source is invalid, SPF struct was not created using `from_str()`
    InvalidSource,
    /// Source string length exceeds 255 Characters
    SourceLengthExceeded,
    /// Exceeds RFC lookup limit.
    ExceedLookup,
    /// Invalid SPF
    InvalidSPF,
    /// Rediect with additional Mechanisms
    RedirectWithAdditionalMechanism,
    /// Network Address is not valid Error.
    InvalidIPAddr(IpNetworkError),
}
impl std::fmt::Display for SpfErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfErrorType::InvalidSource => write!(f, "Source string not valid."),
            SpfErrorType::SourceLengthExceeded => write!(f, "Spf record exceeds 255 characters."),
            SpfErrorType::ExceedLookup => write!(f, "Too many DNS lookups."),
            SpfErrorType::InvalidSPF => write!(f, "Spf record is invalid."),
            SpfErrorType::RedirectWithAdditionalMechanism => {
                write!(f, "Redirect with unexpected additional Mechanisms")
            }
            SpfErrorType::InvalidIPAddr(err) => write!(f, "{}", err.to_string()),
        }
    }
}

impl From<IpNetworkError> for SpfErrorType {
    fn from(err: IpNetworkError) -> Self {
        SpfErrorType::InvalidIPAddr(err)
    }
}

impl std::error::Error for SpfErrorType {}

/// The Definition of the Spf struct which contains all information related a single
/// SPF record.
#[derive(Debug)]
pub struct Spf {
    source: String,
    version: String,
    from_src: bool,
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
}

impl std::fmt::Display for Spf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.build_spf_string() {
            Ok(txt) => write!(f, "{}", txt),
            Err(_) => write!(f, "The Spf record is not valid."),
        }
    }
}
impl Default for Spf {
    fn default() -> Self {
        Self {
            source: String::new(),
            version: String::new(),
            from_src: false,
            redirect: None,
            is_redirected: false,
            a: None,
            mx: None,
            include: None,
            ip4: None,
            ip6: None,
            ptr: None,
            exists: None,
            all: None,
        }
    }
}

impl Spf {
    /// Create a new empty Spf struct.
    pub fn new() -> Self {
        Spf::default()
    }
    /// Create a new Spf with the provided `str`
    ///
    /// # Arguments:
    /// * `str` - a reference to a string slice, which is the SPF record.
    ///
    /// # Example
    ///
    /// ```
    /// use decon_spf::spf::Spf;
    /// let source_str = "v=spf1 redirect=_spf.example.com";
    /// let spf = Spf::from_str(&source_str);
    /// ```
    ///
    pub fn from_str(str: &str) -> Self {
        Self {
            source: str.clone().to_string(),
            version: String::new(),
            from_src: true,
            redirect: None,
            is_redirected: false,
            a: None,
            mx: None,
            include: None,
            ip4: None,
            ip6: None,
            ptr: None,
            exists: None,
            all: None,
        }
    }
    /// Parse the contents of `source` and populate the internal structure of `Spf`  
    ///
    /// # Returns: Result<(), SpfErrorType>  
    /// On Ok() returns ().  
    /// On Err() Returns an invariant of SpfErrorType:
    /// - [`InvalidSource`](SpfErrorType::InvalidSource)
    /// - [`SourceLengthExceeded`](SpfErrorType::SourceLengthExceeded)
    pub fn parse(&mut self) -> Result<(), SpfErrorType> {
        if !self.from_src
            || !self.source.starts_with("v=spf1") && !self.source.starts_with("spf2.0")
        {
            return Err(SpfErrorType::InvalidSource);
        };
        if self.source.len() > 255 {
            return Err(SpfErrorType::SourceLengthExceeded);
        };
        if helpers::spf_has_consecutive_whitespace(self.source.as_str()) {
            return Err(SpfErrorType::InvalidSource);
        }
        let records = self.source.split_whitespace();
        let mut vec_of_includes: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_ip4: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_ip6: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_a: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_mx: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_exists: Vec<Mechanism<String>> = Vec::new();
        for record in records {
            // Consider ensuring we do this once at least and then skip
            if record.contains("v=spf1") || record.starts_with("spf2.0") {
                self.version = record.to_string();
            } else if record.contains("redirect=") {
                // Match a redirect
                let items = record.rsplit("=");
                for item in items {
                    self.redirect =
                        Some(Mechanism::new_redirect(Qualifier::Pass, item.to_string()));
                    break;
                }
                self.is_redirected = true;
            } else if record.contains("include:") {
                // Match an include
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                for item in record.rsplit(":") {
                    vec_of_includes.push(Mechanism::new_include(
                        qualifier_and_modified_str.0,
                        item.to_string(),
                    ));
                    break; // skip the 'include:' side of the split
                }
            } else if record.contains("exists:") {
                // Match exists
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'e');
                for item in record.rsplit(":") {
                    vec_of_exists.push(Mechanism::new_exists(
                        qualifier_and_modified_str.0,
                        item.to_string(),
                    ));
                    break; // Skip the 'exists:' site of the split
                }
            } else if record.contains("ip4:") {
                // Match an ip4
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip4) = qualifier_and_modified_str.1.strip_prefix("ip4:") {
                    let valid_ip4 = raw_ip4.parse();
                    if valid_ip4.is_ok() {
                        // Safe to build Mechanism.
                        let network =
                            Mechanism::new_ip4(qualifier_and_modified_str.0, valid_ip4.unwrap());
                        vec_of_ip4.push(network);
                    } else {
                        // The ip4 string was not valid. Return Err()
                        return Err(SpfErrorType::InvalidIPAddr(valid_ip4.unwrap_err()));
                    }
                }
            } else if record.contains("ip6:") {
                // Match an ip6
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip6) = qualifier_and_modified_str.1.strip_prefix("ip6:") {
                    let valid_ip6 = raw_ip6.parse();
                    if valid_ip6.is_ok() {
                        // Safe to build Mechanism
                        let network =
                            Mechanism::new_ip6(qualifier_and_modified_str.0, valid_ip6.unwrap());
                        vec_of_ip6.push(network);
                    } else {
                        // The ip6 string was not valid. Return Err()
                        return Err(SpfErrorType::InvalidIPAddr(valid_ip6.unwrap_err()));
                    }
                }
            } else if record.ends_with("all") {
                // deal with all if present
                self.all = Some(Mechanism::new_all(
                    return_and_remove_qualifier(record, 'a').0,
                ))
            // Handle A, MX and PTR types.
            } else if let Some(a_mechanism) = helpers::capture_matches(record, MechanismKind::A) {
                vec_of_a.push(a_mechanism);
            } else if let Some(mx_mechanism) = helpers::capture_matches(record, MechanismKind::MX) {
                vec_of_mx.push(mx_mechanism);
            } else if let Some(ptr_mechanism) = helpers::capture_matches(record, MechanismKind::Ptr)
            {
                self.ptr = Some(ptr_mechanism);
            }
        }
        // Move vec_of_* int the SPF struct
        if !vec_of_includes.is_empty() {
            self.include = Some(vec_of_includes);
        };
        if !vec_of_ip4.is_empty() {
            self.ip4 = Some(vec_of_ip4);
        };
        if !vec_of_ip6.is_empty() {
            self.ip6 = Some(vec_of_ip6);
        };
        if !vec_of_a.is_empty() {
            self.a = Some(vec_of_a);
        }
        if !vec_of_mx.is_empty() {
            self.mx = Some(vec_of_mx);
        }
        if !vec_of_exists.is_empty() {
            self.exists = Some(vec_of_exists);
        }
        Ok(())
    }
    /// Check that the source string was parsed and was valid.
    //pub fn source_is_vaid(&self) -> bool {
    //  // Should I check was validated?
    //    self.source_is_valid
    //}
    /// Check that data stored in the Spf Struct is considered a valid Spf Record.
    //pub fn is_valid(&self) -> bool {
    //   // Should I check was validated?
    //  self.spf_is_valid
    //}
    /// Set version to `v=spf1`
    pub fn set_v1(&mut self) {
        self.version = String::from("v=spf1");
    }
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
    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains("v=spf1")
    }
    /// Check that version is v2
    pub fn is_v2(&self) -> bool {
        self.version.starts_with("spf2.0")
    }
    /// Return a reference to version
    pub fn version(&self) -> &String {
        &self.version
    }
    /// Append a Redirect Mechanism to the Spf Struct.
    fn append_mechanism_of_redirect(&mut self, mechanism: Mechanism<String>) {
        self.redirect = Some(mechanism);
        self.is_redirected = true;
        if self.a.is_some() {
            self.a = None;
        }
    }
    /// Clear the passed MechanismKind which has been passed.
    /// Sets the passed mechanism to `None`
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::{Qualifier, MechanismKind, Mechanism};
    /// use decon_spf::spf::Spf;
    /// let mut new_spf_record = Spf::new();
    /// new_spf_record.set_v1();
    /// new_spf_record.append_mechanism(Mechanism::new_all(Qualifier::Pass));
    /// new_spf_record.append_mechanism(Mechanism::new_a_without_mechanism(Qualifier::Pass));
    /// new_spf_record.append_ip_mechanism(Mechanism::new_ip(Qualifier::Pass,
    ///                                                      "203.32.160.0/23".parse().unwrap()));
    /// assert_eq!(new_spf_record.to_string(), "v=spf1 a ip4:203.32.160.0/23 all".to_string());
    /// // Remove ip4 Mechanism
    /// new_spf_record.clear_mechanism(MechanismKind::IpV4);
    /// assert_eq!(new_spf_record.to_string(), "v=spf1 a all".to_string());
    pub fn clear_mechanism(&mut self, kind: MechanismKind) {
        match kind {
            MechanismKind::Redirect => {
                self.redirect = None;
                self.is_redirected = false;
            }
            MechanismKind::A => self.a = None,
            MechanismKind::MX => self.mx = None,
            MechanismKind::Include => self.include = None,
            MechanismKind::IpV4 => self.ip4 = None,
            MechanismKind::IpV6 => self.ip6 = None,
            MechanismKind::Exists => self.exists = None,
            MechanismKind::Ptr => self.ptr = None,
            MechanismKind::All => self.all = None,
        }
    }

    fn append_mechanism_of_a(&mut self, mechanism: Mechanism<String>) {
        let mut vec: Vec<Mechanism<String>> = Vec::new();
        vec.push(mechanism);
        if self.a.is_none() {
            self.a = Some(vec);
        } else {
            self.a.as_mut().unwrap().append(&mut vec);
        }
    }
    fn append_mechanism_of_mx(&mut self, mechanism: Mechanism<String>) {
        let mut vec: Vec<Mechanism<String>> = Vec::new();
        vec.push(mechanism);
        if self.mx.is_none() {
            // Empty vec. Just attach the new vec
            self.mx = Some(vec);
        } else {
            // Already has a vec of values. Append to it.
            self.mx.as_mut().unwrap().append(&mut vec);
        }
    }
    fn append_mechanism_of_include(&mut self, mechanism: Mechanism<String>) {
        let mut vec: Vec<Mechanism<String>> = Vec::new();
        vec.push(mechanism);
        if self.include.is_none() {
            // Empty vec. Just attach the new vec
            self.include = Some(vec);
        } else {
            // Already has a vec of values. Append to it.
            self.include.as_mut().unwrap().append(&mut vec);
        }
    }
    fn append_mechanism_of_ip4(&mut self, mechanism: Mechanism<IpNetwork>) {
        let mut vec: Vec<Mechanism<IpNetwork>> = Vec::new();
        vec.push(mechanism);
        if self.ip4.is_none() {
            // Empty vec. Just attach the new vec
            self.ip4 = Some(vec);
        } else {
            // Already has a vec of values. Append to it.
            self.ip4.as_mut().unwrap().append(&mut vec);
        }
    }
    fn append_mechanism_of_ip6(&mut self, mechanism: Mechanism<IpNetwork>) {
        let mut vec: Vec<Mechanism<IpNetwork>> = Vec::new();
        vec.push(mechanism);
        if self.ip6.is_none() {
            // Empty vec. Just attach the new vec
            self.ip6 = Some(vec);
        } else {
            // Already has a vec of values. Append to it.
            self.ip6.as_mut().unwrap().append(&mut vec);
        }
    }
    fn append_mechanism_of_exists(&mut self, mechanism: Mechanism<String>) {
        let mut vec: Vec<Mechanism<String>> = Vec::new();
        vec.push(mechanism);
        if self.exists.is_none() {
            // Empty vec. Just attach the new vec
            self.exists = Some(vec);
        } else {
            // Already has a vec of values. Append to it.
            self.exists.as_mut().unwrap().append(&mut vec);
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
    /// Appends the passed Mechanism<String> to the SPF struct.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::{Qualifier, Mechanism};
    /// use decon_spf::spf::Spf;
    /// let mut new_spf_record = Spf::new();
    /// new_spf_record.set_v1();
    /// new_spf_record.append_mechanism(Mechanism::new_redirect(Qualifier::Pass,
    ///                                 String::from("_spf.example.com")));
    /// new_spf_record.append_mechanism(Mechanism::new_all(Qualifier::Pass));
    /// assert_eq!(new_spf_record.to_string(), "v=spf1 redirect=_spf.example.com".to_string());
    /// ```
    ///
    /// # Note:
    /// If The Spf is already set as `Redirect` trying to append an `All`
    /// Mechanism will have no affect.
    pub fn append_mechanism(&mut self, mechanism: Mechanism<String>) {
        match mechanism.kind() {
            MechanismKind::Redirect => self.append_mechanism_of_redirect(mechanism),
            MechanismKind::A => self.append_mechanism_of_a(mechanism),
            MechanismKind::MX => self.append_mechanism_of_mx(mechanism),
            MechanismKind::Include => self.append_mechanism_of_include(mechanism),
            MechanismKind::Exists => self.append_mechanism_of_exists(mechanism),
            MechanismKind::Ptr => self.append_mechanism_of_ptr(mechanism),
            MechanismKind::All => self.append_mechanism_of_all(mechanism),
            _ => unreachable!(),
        }
    }
    /// Appends the passed Mechanism<IpNetwork> to the SPF struct.
    ///
    /// # Example:
    /// ```
    /// use decon_spf::mechanism::{Qualifier, Mechanism};
    /// use decon_spf::spf::Spf;
    /// let mut new_spf_record = Spf::new();
    /// new_spf_record.set_v1();
    /// new_spf_record.append_ip_mechanism(Mechanism::new_ip(Qualifier::Pass,
    ///                                 ("203.32.160.0/23").parse().unwrap()));
    /// new_spf_record.append_mechanism(Mechanism::new_all(Qualifier::Pass));
    /// assert_eq!(new_spf_record.to_string(), "v=spf1 ip4:203.32.160.0/23 all".to_string());
    /// ```    
    pub fn append_ip_mechanism(&mut self, mechanism: Mechanism<IpNetwork>) {
        match mechanism.kind() {
            MechanismKind::IpV4 => self.append_mechanism_of_ip4(mechanism),
            MechanismKind::IpV6 => self.append_mechanism_of_ip6(mechanism),
            _ => {
                unreachable!()
            }
        }
    }
    /// # Note: Experimential
    /// Do not use.
    /// Very rudementary validation check.
    /// - Will fail if the length of `source` is more than 255 characters See: [`SourceLengthExceeded`](SpfErrorType::SourceLengthExceeded)
    /// - Will fail if there are more than 10 DNS lookups. Looks are required for each 'A', 'MX' and 'Include' Mechanism. See: [`ExceedLookup`](SpfErrorType::ExceedLookup)
    /// (This will change given new information)
    pub fn try_validate(&self) -> Result<(), SpfErrorType> {
        if self.from_src {
            if self.source.len() > 255 {
                return Err(SpfErrorType::SourceLengthExceeded);
            };
        };
        // Rediect should be the only mechanism present. Any additional values are not permitted.
        if self.redirect().is_some()
            && (self.a().is_some()
                || self.mx().is_some()
                || self.includes().is_some()
                || self.exists().is_some()
                || self.ptr().is_some()
                || self.ip4().is_some()
                || self.ip6().is_some()
                || self.all().is_some())
        {
            return Err(SpfErrorType::RedirectWithAdditionalMechanism);
        }
        let mut lookup_count = 0;
        {
            if self.redirect().is_some() {
                lookup_count += 1;
            } else {
                if self.a().is_some() {
                    lookup_count += self.a().unwrap().len();
                }
                if self.mx().is_some() {
                    lookup_count += self.mx().unwrap().len();
                }
                if self.includes().is_some() {
                    lookup_count += self.includes().unwrap().len();
                }
            }
            if lookup_count > 10 {
                return Err(SpfErrorType::ExceedLookup);
            }
        }
        Ok(())
    }
    fn build_spf_string(&self) -> Result<String, SpfErrorType> {
        let valid = self.try_validate();
        if valid.is_err() {
            Err(valid.err().unwrap())
        } else {
            let mut spf = String::new();
            spf.push_str(self.version());
            if self.is_redirected {
                spf.push_str(" ");
                spf.push_str(self.redirect().unwrap().to_string().as_str());
            } else {
                if self.a().is_some() {
                    spf.push_str(helpers::build_spf_str(self.a()).as_str());
                };
                if self.mx().is_some() {
                    spf.push_str(helpers::build_spf_str(self.mx()).as_str());
                };
                if self.includes().is_some() {
                    spf.push_str(helpers::build_spf_str(self.includes()).as_str());
                }
                if self.ip4().is_some() {
                    spf.push_str(helpers::build_spf_str_from_ip(self.ip4()).as_str());
                }
                if self.ip6().is_some() {
                    spf.push_str(helpers::build_spf_str_from_ip(self.ip6()).as_str());
                }
                if self.exists().is_some() {
                    spf.push_str(helpers::build_spf_str(self.exists()).as_str());
                }
                if self.ptr().is_some() {
                    spf.push_str(" ");
                    spf.push_str(self.ptr().unwrap().to_string().as_str());
                }
                // All can only be used if this is not a redirect.
                if !self.is_redirected {
                    if self.all().is_some() {
                        spf.push_str(" ");
                        spf.push_str(self.all().unwrap().to_string().as_str());
                    }
                }
            }
            return Ok(spf);
        }
    }
    /// Returns a new string representation of the spf record if possible.
    /// This does not use the `source` attribute.
    #[deprecated(note = "This will be deprecated in the future. Use to_string() instead.")]
    pub fn as_spf(&self) -> Result<String, SpfErrorType> {
        self.build_spf_string()
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
    /// Returns a reference to the a `Vec` of `Mechanism<String>` for `A`
    pub fn a(&self) -> Option<&Vec<Mechanism<String>>> {
        self.a.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<String>` for `MX`
    pub fn mx(&self) -> Option<&Vec<Mechanism<String>>> {
        self.mx.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<IpNetwork>` for `IP4`
    pub fn ip4(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip4.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<IpNetwork>` for `IP6`
    pub fn ip6(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip6.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<String>` for `Exists`
    pub fn exists(&self) -> Option<&Vec<Mechanism<String>>> {
        self.exists.as_ref()
    }
    /// Returns a reference to the a `Vec` of `Mechanism<String>` for `Ptr`
    pub fn ptr(&self) -> Option<&Mechanism<String>> {
        self.ptr.as_ref()
    }
    /// Returns a reference to `Mechanism<String>` for `All`
    pub fn all(&self) -> Option<&Mechanism<String>> {
        self.all.as_ref()
    }
}
#[doc(hidden)]
// Check if the initial character in the string `record` matches `c`
// If they do no match then return the initial character
// if c matches first character of record, we can `+`, a blank modiifer equates to `+`
fn return_and_remove_qualifier(record: &str, c: char) -> (Qualifier, &str) {
    // Returns a tuple of (qualifier, &str)
    // &str will have had the qualifier character removed if it existed. The &str will be unchanged
    // if the qualifier was not present
    if c != record.chars().nth(0).unwrap() {
        // qualifier exists. return tuple of qualifier and `record` with qualifier removed.
        (
            helpers::char_to_qualifier(record.chars().nth(0).unwrap()),
            remove_qualifier(record),
        )
    } else {
        // qualifier does not exist, default to `+` and return unmodified `record`
        (Qualifier::Pass, record)
    }
}
#[test]
fn return_and_remove_qualifier_no_qualifier() {
    let source = "no prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Pass, c);
    assert_eq!(source, new_str);
}
#[test]
fn return_and_remove_qualifier_pass() {
    let source = "+prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Pass, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_fail() {
    let source = "-prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Fail, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_softfail() {
    let source = "~prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::SoftFail, c);
    assert_eq!("prefix", new_str);
}
#[test]
fn return_and_remove_qualifier_neutral() {
    let source = "?prefix";
    let (c, new_str) = return_and_remove_qualifier(source, 'n');
    assert_eq!(Qualifier::Neutral, c);
    assert_eq!("prefix", new_str);
}
#[doc(hidden)]
fn remove_qualifier(record: &str) -> &str {
    // Remove leading (+,-,~,?) character and return an updated str
    let mut chars = record.chars();
    chars.next();
    chars.as_str()
}
#[test]
fn test_remove_qualifier() {
    let test_str = "abc";
    let result = remove_qualifier(test_str);
    assert_eq!(result, "bc");
}
