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
//! - Check and Set Spf record version. See: [`Spf Versions`](SpfBuilder::set_v1)
//! - Check and Create Spf Mechanism/Modifiers:
//!     - [`Mechanism`](mechanism::Mechanism)
//!     - [`Mechanism::Qualifier`](mechanism::Mechanism::is_pass)
//!     - [`Mechanism::Kind`](mechanism::Mechanism::kind)
//!
//! # Feature Flags:
//! - `ptr` (Enabled by default.)  
//!    This feature will impact a future validation feature.
//! - `strict-dns` (Disabled by default.)  
//!   This enables syntactical checking of Domain Names.
//!     - When enabled it changes the behaviour of `FromStr` for `Mechanism<String>` and
//! `ParsedMechanism`. By default, `rrdata` is not checked.\
//!   When `strict-dns` is enabled an invalid domain host will be seen as **Hard** error.
//! Any additional parsing will be halted.
//! - `builder` (Disabled by default.)\
//!   This enables the use of [SpfBuilder] and its related features\
//!   You are able to convert and `Spf<String>` `into()` an `SpfBuilder` Struct.
//! - `spf2` (Disabled by default)  
//!   This enables the ability to programmatically create Spf2 (SenderID) records. As this
//!   has become defunct. There is no real need for it. But it remains as an option if desired.
//! - `serde` (Disabled by default.)
//!
mod core;
mod spf;

#[cfg(feature = "builder")]
pub use crate::spf::builder::SpfBuilder;
pub use crate::spf::errors::SpfErrors;
pub use crate::spf::{Spf, SpfError};
pub use spf::mechanism::{self};
