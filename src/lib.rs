#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! This crate is responsible for providing tools to access and modify information about spf records.  
//! Provides methods for building spf records programmatically.  
//!
//!
//! For a list of supported *Modifiers* and *Mechanism*. See [`Kind`](mechanism::Kind)  
//!
//! This crate is able to deconstruct `v=spf1` and `spf2.0` records.
//!
//! # Abilities:
//! - Check and Set Spf record version: [`Spf Versions`](spf::Spf::set_v1)
//! - Check and Create Spf Mechanism/Modifiers:
//!     - [`Mechanism`](mechanism::Mechanism)
//!     - [`Check Qualifier Type`](mechanism::Mechanism::is_pass)
//!     - [`Check Mechanism Type`](mechanism::Mechanism::kind)
//!
//! # Feature Flags:
//! - `warn-dns` (Disabled by default.)
//!
//!   This enables syntactical checking of Domain Names.
//!
mod helpers;
pub mod mechanism;
mod spf;

//use crate::mechanism::Mechanism;
pub use crate::spf::Spf;
pub use crate::spf::SpfError;
