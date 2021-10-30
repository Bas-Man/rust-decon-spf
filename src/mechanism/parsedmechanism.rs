use crate::mechanism::{Kind, Mechanism, MechanismError, Qualifier};
use ipnetwork::IpNetwork;

use std::{convert::TryFrom, str::FromStr};

/// This enum stores the result of a successful parsing of a Mechanism String.  
/// This will either contain a Mechanism holding a `String` or Mechanism holding a `IpNetwork`
#[derive(Debug)]
pub enum ParsedMechanism {
    /// This variant represents a Mechanism containing a String  
    TXT(Mechanism<String>),
    /// This variant represents a Mechanism containing an IpNetwork  
    IP(Mechanism<IpNetwork>),
}

impl std::fmt::Display for ParsedMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            ParsedMechanism::TXT(ref m) => write!(f, "{}", m.to_string()),
            ParsedMechanism::IP(ref m) => write!(f, "{}", m.to_string()),
        }
    }
}

/// Emplement `from_str` for ParsedMechanism.  
/// Provides the ability to parse any supported `Spf Mechanisms`. See [`Kind`](Kind)
/// # Examples:
///```rust
/// use decon_spf::mechanism::{ParsedMechanism, MechanismError};
/// let mechanism_a: ParsedMechanism = "a:test.com/24".parse().unwrap();
/// let mechanism_mx = "mx:example.com".parse::<ParsedMechanism>().unwrap();
/// let mechanism_ip4 = "ip4:203.32.160.10/24".parse::<ParsedMechanism>().unwrap();
///
/// let mechanism_not_ip4 = "ip4:example.com".parse::<ParsedMechanism>();
/// assert_eq!(mechanism_not_ip4.is_err(), true);
/// assert_eq!(mechanism_not_ip4.unwrap_err(),
///            MechanismError::NotValidIPNetwork("invalid address: example.com".to_string()));
///
/// let mechanism_malformed: Result<ParsedMechanism, MechanismError> = "ab.com".parse::<ParsedMechanism>();
/// assert_eq!(mechanism_malformed.unwrap_err().to_string(),
///            "ab.com does not conform to any Mechanism format.");
///```
impl FromStr for ParsedMechanism {
    type Err = MechanismError;

    fn from_str(s: &str) -> Result<ParsedMechanism, Self::Err> {
        if s.contains("ip4:") || s.contains("ip6:") {
            Ok(ParsedMechanism::IP(Mechanism::<IpNetwork>::from_str(s)?))
        } else {
            Ok(ParsedMechanism::TXT(Mechanism::<String>::from_str(s)?))
        }
    }
}
impl TryFrom<&str> for ParsedMechanism {
    type Error = MechanismError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        ParsedMechanism::from_str(s)
    }
}
impl ParsedMechanism {
    /// Provides another way to parse `Spf Mechanisms`
    /// # Example:
    ///```rust
    /// use decon_spf::mechanism::ParsedMechanism;
    /// let parsed_mechanism = ParsedMechanism::new("ptr").unwrap();
    /// let mechanism = parsed_mechanism.txt();
    /// assert_eq!(mechanism.kind().is_ptr(), true);
    ///```
    pub fn new(s: &str) -> Result<ParsedMechanism, MechanismError> {
        if s.contains("ip4:") || s.contains("ip6:") {
            Ok(ParsedMechanism::IP(Mechanism::<IpNetwork>::from_str(s)?))
        } else {
            Ok(ParsedMechanism::TXT(Mechanism::<String>::from_str(s)?))
        }
    }
    /// Create a `Redirect` Mechanism from `&str`
    /// # Example:
    ///```rust
    /// use decon_spf::mechanism::ParsedMechanism;
    /// use decon_spf::mechanism::Qualifier;
    /// let parsed_mechanism = ParsedMechanism::new_redirect(Qualifier::Pass, "_spf.example.com");
    /// let m = parsed_mechanism.txt();
    /// assert_eq!(m.to_string(), "redirect=_spf.example.com");
    ///```    
    #[doc(hidden)]
    pub fn new_redirect(qualifier: Qualifier, s: &str) -> ParsedMechanism {
        ParsedMechanism::TXT(Mechanism::new_redirect(qualifier, s.to_string()))
    }
    #[doc(hidden)]
    pub fn new_a(q: Qualifier, m: Option<String>) -> ParsedMechanism {
        if let Some(m) = m {
            ParsedMechanism::TXT(Mechanism::new_a_with_mechanism(q, m))
        } else {
            ParsedMechanism::TXT(Mechanism::new_a_without_mechanism(q))
        }
    }
    #[doc(hidden)]
    pub fn new_mx(q: Qualifier, m: Option<String>) -> ParsedMechanism {
        if let Some(m) = m {
            ParsedMechanism::TXT(Mechanism::new_mx_with_mechanism(q, m))
        } else {
            ParsedMechanism::TXT(Mechanism::new_mx_without_mechanism(q))
        }
    }
    #[doc(hidden)]
    pub fn new_include(q: Qualifier, m: String) -> Mechanism<String> {
        Mechanism::new_include(q, m)
    }
    #[doc(hidden)]
    pub fn new_ip(q: Qualifier, ip: IpNetwork) -> ParsedMechanism {
        ParsedMechanism::IP(Mechanism::new_ip(q, ip))
    }
    #[doc(hidden)]
    pub fn new_exists(q: Qualifier, m: String) -> Mechanism<String> {
        Mechanism::new_exists(q, m)
    }
    #[doc(hidden)]
    pub fn new_ptr(q: Qualifier, m: Option<String>) -> Mechanism<String> {
        if let Some(m) = m {
            Mechanism::new_ptr_with_mechanism(q, m)
        } else {
            Mechanism::new_ptr_without_mechanism(q)
        }
    }
    #[doc(hidden)]
    pub fn new_all(q: Qualifier) -> ParsedMechanism {
        ParsedMechanism::TXT(Mechanism::new_all(q))
    }
    /// Provides the ability to extract a `Spf Mechanism` which is not `ip4` or ip6`
    /// Example:
    ///```rust
    /// use decon_spf::mechanism::{ParsedMechanism,Mechanism};
    /// let parsed_mechanism = ParsedMechanism::new("mx").unwrap();
    /// let mechanism = parsed_mechanism.txt();
    /// assert_eq!(mechanism.kind().is_mx(), true);
    ///```
    pub fn txt(&self) -> Mechanism<String> {
        match *self {
            ParsedMechanism::TXT(ref m) => {
                Mechanism::<String>::from_str(m.to_string().as_str()).unwrap()
            }
            ParsedMechanism::IP(_) => unreachable!(),
        }
    }
    /// Provides the ability to extract a `Spf Mechanism` which is either a `ip4` or ip6`
    /// Example:
    ///```rust
    /// use decon_spf::mechanism::{ParsedMechanism,Mechanism};
    /// let parsed_mechanism = ParsedMechanism::new("ip4:203.32.160.0/24").unwrap();
    /// let mechanism = parsed_mechanism.network();
    /// assert_eq!(mechanism.kind().is_ip_v4(), true);
    ///```
    pub fn network(&self) -> Mechanism<IpNetwork> {
        match *self {
            ParsedMechanism::IP(ref m) => Mechanism::new_ip(*m.qualifier(), *m.as_network()),
            ParsedMechanism::TXT(_) => unreachable!(),
        }
    }
    #[allow(dead_code)]
    fn kind(&self) -> &Kind {
        match *self {
            ParsedMechanism::TXT(ref m) => m.kind(),
            ParsedMechanism::IP(ref m) => m.kind(),
        }
    }
    #[allow(dead_code)]
    fn qualifier(&self) -> &Qualifier {
        match *self {
            ParsedMechanism::TXT(ref m) => m.qualifier(),
            ParsedMechanism::IP(ref m) => m.qualifier(),
        }
    }
    #[allow(dead_code)]
    fn raw(&self) -> String {
        match *self {
            ParsedMechanism::TXT(ref m) => m.raw(),
            ParsedMechanism::IP(ref m) => m.raw(),
        }
    }
    #[doc(hidden)]
    pub fn is_network(&self) -> bool {
        match *self {
            ParsedMechanism::TXT(_) => false,
            ParsedMechanism::IP(_) => true,
        }
    }
    #[allow(dead_code)]
    fn as_network(&self) -> Result<&IpNetwork, MechanismError> {
        match *self {
            ParsedMechanism::TXT(_) => Err(MechanismError::NotIpNetworkMechanism),
            ParsedMechanism::IP(ref m) => Ok(m.as_network()),
        }
    }
}
