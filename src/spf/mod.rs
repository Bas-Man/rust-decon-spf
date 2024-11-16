//! This module allows you to deconstruct an existing SPF DNS record into its
//! constituent parts.  
//! It is not intended to validate the spf record.

pub mod builder;
mod errors;
pub mod mechanism;
#[cfg(test)]
mod tests;
mod validate;

use crate::core;
pub use crate::spf::errors::SpfError;
use ipnetwork::IpNetwork;
use mechanism::Kind;
pub use mechanism::Mechanism;
// Make this public in the future
use crate::spf::validate::Validate;
use std::fmt::{Debug, Display, Formatter};
use std::{convert::TryFrom, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Base struct for an Spf of any type.
#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Spf<T> {
    source: T,
    version: T,
    redirect_idx: usize,
    all_idx: usize,
    mechanisms: Vec<Mechanism<T>>,
}

pub struct SpfIterator<'a, T> {
    mechanism_iter: std::slice::Iter<'a, Mechanism<T>>,
}

impl<'a, T> Iterator for SpfIterator<'a, T> {
    type Item = &'a Mechanism<T>; // Change the Item type to Mechanism<T>

    fn next(&mut self) -> Option<Self::Item> {
        self.mechanism_iter.next()
    }
}

impl<T> Spf<T>
where
    T: Default,
    T: Debug,
    T: Display,
{
    /// Access the version attribute associated with the Spf record.
    pub fn version(&self) -> &T {
        &self.version
    }
    /// Iterate over the Spf Mechanisms of the Spf Record. This does not return the Spf `version`
    pub fn iter(&self) -> SpfIterator<'_, T> {
        SpfIterator {
            mechanism_iter: self.mechanisms.iter(),
        }
    }
}

impl<T> IntoIterator for Spf<T> {
    type Item = Mechanism<T>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.mechanisms.into_iter()
    }
}

impl Display for Spf<String> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !&self.source.is_empty() {
            write!(f, "{}", self.source)
        } else {
            let mut spf_string = String::new();
            spf_string.push_str(self.version().as_str());
            for m in self.iter() {
                spf_string.push_str(format!(" {}", m).as_str());
            }
            write!(f, "{}", spf_string)
        }
    }
}

impl FromStr for Spf<String> {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;
        validate::check_whitespaces(s)?;

        // Index of Redirect Mechanism
        let mut redirect_idx: usize = 0;
        // There exists a redirect mechanism
        let mut redirect = false;
        // Index of All Mechanism
        let mut all_idx = 0;
        let mut idx = 0;
        let mut spf = Spf::default();
        let mechanisms = s.split_whitespace();
        for m in mechanisms {
            if m.contains(core::SPF1) {
                spf.version = m.to_string();
            } else if m.contains(core::IP4) || m.contains(core::IP6) {
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
                idx += 1;
            }
        }
        if redirect {
            // all_idx should not be greater han redirect_idx.
            // all_idx should be 0 if a redirect mechanism was parsed.
            if all_idx > redirect_idx {
                return Err(SpfError::RedirectWithAllMechanism);
            }
            // redirect_idx should be the last item if it exists.
            if redirect_idx != idx - 1 {
                return Err(SpfError::RedirectNotFinalMechanism(redirect_idx as u8));
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
    /// Creates a `Spf<String>` from the passed str reference.
    /// This is basically a rapper around FromStr which has been implemented for `Spf<String>`
    #[allow(dead_code)]
    pub fn new(s: &str) -> Result<Self, SpfError> {
        s.parse::<Spf<String>>()
    }

    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains(core::SPF1)
    }
    /// Give access to the redirect modifier if present
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
            Some(&self.mechanisms[self.redirect_idx])
        }
    }
    /// Give access to the `all` mechanism if it is present.
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
            Some(&self.mechanisms[self.all_idx])
        }
    }
    #[allow(dead_code)]
    fn validate(&self) -> Result<(), SpfError> {
        self.validate_version()?;
        self.validate_length()?;
        #[cfg(feature = "ptr")]
        self.validate_ptr()?;
        self.validate_lookup_count()?;
        self.validate_redirect_all()?;
        Ok(())
    }
}
