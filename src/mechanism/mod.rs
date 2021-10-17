//! This module contains the tools and functions to dealing with Mechanisms found within an Spf DNS record.  
//!
//! t
mod kind;
mod mechanism;
mod qualifier;
mod tests;

pub use kind::Kind;
pub use mechanism::Mechanism;
pub use qualifier::Qualifier;
