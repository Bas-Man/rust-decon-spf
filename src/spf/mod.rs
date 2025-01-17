//! This module allows you to deconstruct an existing SPF DNS record into its
//! constituent parts.  

#[cfg_attr(docsrs, doc(cfg(feature = "builder")))]
#[cfg(feature = "builder")]
pub mod builder;
pub mod errors;
pub mod mechanism;
mod string;
#[cfg(test)]
mod tests;
mod validate;

pub use crate::spf::errors::SpfError;
pub use mechanism::Mechanism;
use std::fmt::{Debug, Display};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Base struct for an Spf of any type.
#[derive(Debug, Default, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Spf {
    source: String,
    version: String,
    redirect_idx: usize,
    has_redirect: bool,
    all_idx: usize,
    lookup_count: u8,
    mechanisms: Vec<Mechanism<String>>,
}

pub struct SpfIterator<'a> {
    mechanism_iter: std::slice::Iter<'a, Mechanism<String>>,
}

impl<'a> Iterator for SpfIterator<'a> {
    type Item = &'a Mechanism<String>; // Change the Item type to Mechanism<T>

    fn next(&mut self) -> Option<Self::Item> {
        self.mechanism_iter.next()
    }
}

impl Spf {
    /// Access the version attribute associated with the Spf record.
    pub fn version(&self) -> &String {
        &self.version
    }
    /// Access the number of DNS lookups required for this Spf record.
    pub fn lookup_count(&self) -> u8 {
        self.lookup_count
    }
    /// Iterate over the Spf Mechanisms of the Spf Record. This does not return the Spf `version`,
    /// but iterates over the mechanisms contained within the Spf record.
    pub fn iter(&self) -> SpfIterator<'_> {
        SpfIterator {
            mechanism_iter: self.mechanisms.iter(),
        }
    }
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.mechanisms.len()
    }
}

impl IntoIterator for Spf {
    type Item = Mechanism<String>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.mechanisms.into_iter()
    }
}
