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
//! - Check and Set Spf record version. See: [`Spf Versions`](spf::Spf::set_v1)
//! - Check and Create Spf Mechanism/Modifiers:
//!     - [`Mechanism`](mechanism::Mechanism)
//!     - [`Mechanism Qualifier`](mechanism::Mechanism::is_pass)
//!     - [`Mechanism Kind`](mechanism::Mechanism::kind)
//!
//! # Feature Flags:
//! - `warn-dns` (Disabled by default.)
//!     - This feature only applies to the Spf Parser and only warns of possible problems.
//! - `strict-dns` (Disabled by default.)  
//!   This enables syntactical checking of Domain Names.
//!     - When enabled it changes the behaviour of `FromStr` for `Mechanism<String>` and
//! `ParsedMechanism`. By default `Mechanism<String>`'s `rrdata` is not checked.
//! - `serde` (Disabled by default.)
//!
mod helpers;
pub mod mechanism;
mod spf;

//use crate::mechanism::Mechanism;
pub use crate::spf::Spf;
pub use crate::spf::SpfError;
