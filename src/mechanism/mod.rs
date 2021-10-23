//! This module contains the tools and functions to dealing with Mechanisms found within an Spf DNS record.  
//!
mod errors;
mod kind;
mod mechanismimpl;
mod qualifier;
mod tests;

pub use errors::MechanismError;
use ipnetwork::IpNetwork;
pub use kind::Kind;
#[doc(hidden)]
pub use mechanismimpl::MechanismImpl;
pub use qualifier::Qualifier;

use std::str::FromStr;

pub enum Mechanism {
    String(MechanismImpl<String>),
    IP(MechanismImpl<IpNetwork>),
}

impl FromStr for Mechanism {
    type Err = MechanismError;

    fn from_str(s: &str) -> Result<Mechanism, Self::Err> {
        if s.contains("ip4:") || s.contains("ip6:") {
            Ok(Mechanism::IP(MechanismImpl::from_str(s)?))
        } else {
            Ok(Mechanism::String(MechanismImpl::from_str(s)?))
        }
    }
}
impl Mechanism {
    pub fn new_redirect(q: Qualifier, s: &str) -> MechanismImpl<String> {
        MechanismImpl::new_redirect(q, s.to_string())
    }
    pub fn new_a(q: Qualifier, m: Option<String>) -> MechanismImpl<String> {
        if let Some(m) = m {
            MechanismImpl::new_a_with_mechanism(q, m)
        } else {
            MechanismImpl::new_a_without_mechanism(q)
        }
    }
    pub fn new_mx(q: Qualifier, m: Option<String>) -> MechanismImpl<String> {
        if let Some(m) = m {
            MechanismImpl::new_mx_with_mechanism(q, m)
        } else {
            MechanismImpl::new_mx_without_mechanism(q)
        }
    }
    pub fn new_include(q: Qualifier, m: String) -> MechanismImpl<String> {
        MechanismImpl::new_include(q, m)
    }
    pub fn new_ip(q: Qualifier, ip: IpNetwork) -> MechanismImpl<IpNetwork> {
        MechanismImpl::new_ip(q, ip)
    }
    pub fn new_exists(q: Qualifier, m: String) -> MechanismImpl<String> {
        MechanismImpl::new_exists(q, m)
    }
    pub fn new_ptr(q: Qualifier, m: Option<String>) -> MechanismImpl<String> {
        if let Some(m) = m {
            MechanismImpl::new_ptr_with_mechanism(q, m)
        } else {
            MechanismImpl::new_ptr_without_mechanism(q)
        }
    }
    pub fn new_all(q: Qualifier) -> MechanismImpl<String> {
        MechanismImpl::new_all(q)
    }
    pub fn kind(&self) -> &Kind {
        match *self {
            Mechanism::String(ref m) => m.kind(),
            Mechanism::IP(ref m) => m.kind(),
        }
    }
    pub fn qualifier(&self) -> &Qualifier {
        match *self {
            Mechanism::String(ref m) => m.qualifier(),
            Mechanism::IP(ref m) => m.qualifier(),
        }
    }
}
