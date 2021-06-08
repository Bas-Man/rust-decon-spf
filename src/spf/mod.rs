//! This module allows you to deconstruct an exiting SPF DNS Record into its
//! constituent parts.  
//! It is not intended to validate the spf record.

mod helpers;
pub mod kinds;
pub mod mechanism;
pub mod qualifier;
#[doc(hidden)]
mod tests;

use crate::spf::mechanism::Mechanism;
use crate::spf::qualifier::Qualifier;
use ipnetwork::IpNetwork;
use regex::Regex;

#[derive(Debug)]
pub struct Spf {
    source: String,
    version: String,
    from_src: bool,
    include: Option<Vec<Mechanism<String>>>,
    redirect: Option<Mechanism<String>>,
    is_redirected: bool,
    a: Option<Vec<Mechanism<String>>>,
    mx: Option<Vec<Mechanism<String>>>,
    ip4: Option<Vec<Mechanism<IpNetwork>>>,
    ip6: Option<Vec<Mechanism<IpNetwork>>>,
    ptr: Option<Mechanism<String>>,
    exists: Option<Vec<Mechanism<String>>>,
    all: Option<Mechanism<String>>,
}

impl Default for Spf {
    fn default() -> Self {
        Self {
            source: String::new(),
            version: String::new(),
            from_src: false,
            include: None,
            redirect: None,
            is_redirected: false,
            a: None,
            mx: None,
            ip4: None,
            ip6: None,
            ptr: None,
            exists: None,
            all: None,
        }
    }
}

impl Spf {
    /// Create a new Spf with the provided `str`
    ///
    /// # Example
    ///
    /// ```
    /// use decon_spf::spf::Spf;
    /// let source_str = "v=spf1 redirect=_spf.example.com";
    /// let spf = Spf::from_str(&source_str.to_string());
    /// ```
    ///
    pub fn from_str(str: &String) -> Self {
        Self {
            source: str.clone(),
            version: String::new(),
            from_src: true,
            include: None,
            redirect: None,
            is_redirected: false,
            a: None,
            mx: None,
            ip4: None,
            ip6: None,
            ptr: None,
            exists: None,
            all: None,
        }
    }
    pub fn new() -> Self {
        Spf::default()
    }
    /// Parse the contents of `source` and populate the internal structure of `Spf`
    pub fn parse(&mut self) {
        // # TODO: This needs to have a test for emtpy source. return a Result?
        // initialises required variables.
        let records = self.source.split_whitespace();
        let mut vec_of_includes: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_ip4: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_ip6: Vec<Mechanism<IpNetwork>> = Vec::new();
        let mut vec_of_a: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_mx: Vec<Mechanism<String>> = Vec::new();
        let mut vec_of_exists: Vec<Mechanism<String>> = Vec::new();
        for record in records {
            // Make this lazy.
            let a_pattern =
                Regex::new(r"^(?P<qualifier>[+?~-])?a(?P<mechanism>[:/]{0,1}.+)?").unwrap();
            let mx_pattern =
                Regex::new(r"^(?P<qualifier>[+?~-])?mx(?P<mechanism>[:/]{0,1}.+)?").unwrap();
            let ptr_pattern =
                Regex::new(r"^(?P<qualifier>[+?~-])?ptr(?P<mechanism>[:]{0,1}.+)?").unwrap();
            if record.contains("redirect=") {
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
                    break; // skip the 'include:'
                }
            } else if record.contains("exists:") {
                // Match exists
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'e');
                for item in record.rsplit(":") {
                    vec_of_exists.push(Mechanism::new_exists(
                        qualifier_and_modified_str.0,
                        item.to_string(),
                    ));
                    break;
                }
            } else if record.contains("ip4:") {
                // Match an ip4
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip4) = qualifier_and_modified_str.1.strip_prefix("ip4:") {
                    let network =
                        Mechanism::new_ip4(qualifier_and_modified_str.0, raw_ip4.parse().unwrap());
                    vec_of_ip4.push(network);
                }
            } else if record.contains("ip6:") {
                // Match an ip6
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip6) = qualifier_and_modified_str.1.strip_prefix("ip6:") {
                    let network =
                        Mechanism::new_ip6(qualifier_and_modified_str.0, raw_ip6.parse().unwrap());
                    vec_of_ip6.push(network);
                }
            } else if record.ends_with("all") {
                // deal with all if present
                self.all = Some(Mechanism::new_all(
                    return_and_remove_qualifier(record, 'a').0,
                ))
            } else if let Some(a_mechanism) =
                helpers::capture_matches(a_pattern, record, kinds::MechanismKind::A)
            {
                vec_of_a.push(a_mechanism);
            } else if let Some(mx_mechanism) =
                helpers::capture_matches(mx_pattern, record, kinds::MechanismKind::MX)
            {
                vec_of_mx.push(mx_mechanism);
            } else if let Some(ptr_mechanism) =
                helpers::capture_matches(ptr_pattern, record, kinds::MechanismKind::Ptr)
            {
                self.ptr = Some(ptr_mechanism);
            }
        }
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
    }

    pub fn set_v1(&mut self) {
        self.version = String::from("v=spf1");
    }
    pub fn set_v2_pra(&mut self) {
        self.version = String::from("spf2.0/pra");
    }
    pub fn set_v2_mfrom(&mut self) {
        self.version = String::from("spf2.0/mfrom");
    }
    pub fn set_v2_pra_mfrom(&mut self) {
        self.version = String::from("spf2.0/pra,mfrom");
    }
    pub fn set_v2_mfrom_pra(&mut self) {
        self.version = String::from("spf2.0/mfrom,pra");
    }
    pub fn version(&self) -> &String {
        &self.version
    }
    pub fn is_v1(&self) -> bool {
        self.version.contains("v=spf1")
    }
    pub fn is_v2(&self) -> bool {
        self.version.starts_with("spf2.0")
    }
    pub fn append_mechanism_of_a(&mut self, mechanism: Mechanism<String>) {
        let mut vec: Vec<Mechanism<String>> = Vec::new();
        vec.push(mechanism);
        if self.a.is_none() {
            self.a = Some(vec);
        } else {
            self.a.as_mut().unwrap().append(&mut vec);
        }
    }
    pub fn is_valid(&self) -> bool {
        if self.from_src {
            if self.includes().unwrap().len() > 10 {
                return false;
            };
            if self.source.len() > 255 {
                return false;
            };
        };
        true
    }
    pub fn as_spf(&self) -> Option<String> {
        if !self.is_valid() {
            None
        } else {
            let mut spf = String::new();
            spf.push_str(self.version());
            if self.is_redirected {
                spf.push_str(" ");
                spf.push_str(self.redirect().unwrap().string().as_str());
            } else {
                if self.a().is_some() {
                    for i in self.a().unwrap().iter() {
                        spf.push_str(" ");
                        spf.push_str(i.string().as_str());
                    }
                };
                if self.mx().is_some() {
                    for i in self.mx().unwrap().iter() {
                        spf.push_str(" ");
                        spf.push_str(i.string().as_str());
                    }
                };
                if self.includes().is_some() {
                    for i in self.includes().unwrap().iter() {
                        spf.push_str(" ");
                        spf.push_str(i.string().as_str());
                    }
                }
                // All can only be used if this is not a redirect.
                if !self.is_redirected {
                    if self.all().is_some() {
                        spf.push_str(" ");
                        spf.push_str(self.all().unwrap().string().as_str());
                    }
                }
            }
            return Some(spf);
        }
    }
    pub fn source(&self) -> &String {
        &self.source
    }
    pub fn includes(&self) -> Option<&Vec<Mechanism<String>>> {
        self.include.as_ref()
    }
    pub fn list_includes(&self) {
        match &self.include {
            None => println!("There are no include elements"),
            Some(elements) => {
                println!("Include Mechanisms:");
                for element in elements {
                    println!("{}", element.string());
                }
            }
        }
    }
    pub fn a(&self) -> Option<&Vec<Mechanism<String>>> {
        self.a.as_ref()
    }
    pub fn mx(&self) -> Option<&Vec<Mechanism<String>>> {
        self.mx.as_ref()
    }
    pub fn ip4(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip4.as_ref()
    }
    pub fn ip4_networks(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 networks"),
            Some(record) => {
                println!("List of ip4 networks/hosts:");
                for item in record {
                    println!("{}", item.raw());
                    print!("Network: {}", item.as_network().network());
                    println!(" Subnet: {}", item.as_network().prefix());
                }
            }
        }
    }
    pub fn ip4_mechanisms(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 spf records."),
            Some(records) => {
                println!("\nList of ip4 mechanisms:");
                for record in records {
                    println!("{}", record.string())
                }
            }
        }
    }
    pub fn ip6(&self) -> Option<&Vec<Mechanism<IpNetwork>>> {
        self.ip6.as_ref()
    }
    pub fn ip6_networks(&self) {
        match &self.ip6 {
            None => println!("There are no ip6 networks"),
            Some(record) => {
                println!("List of ip6 networks/hosts:");
                for item in record {
                    println!("{}", item.raw());
                    print!("Network: {}", item.mechanism().network());
                    println!(" Subnet: {}", item.mechanism().prefix());
                }
            }
        }
    }
    pub fn ip6_mechanisms(&self) {
        match &self.ip6 {
            None => println!("There are no ip6 spf records."),
            Some(records) => {
                println!("\nList of ip6 mechanisms:");
                for record in records {
                    println!("{}", record.string())
                }
            }
        }
    }

    pub fn is_redirect(&self) -> bool {
        self.is_redirected
    }
    pub fn redirect(&self) -> Option<&Mechanism<String>> {
        self.redirect.as_ref()
    }
    pub fn exists(&self) -> Option<&Vec<Mechanism<String>>> {
        self.exists.as_ref()
    }
    pub fn ptr(&self) -> Option<&Mechanism<String>> {
        self.ptr.as_ref()
    }
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
