#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! This crate is responsible for providing tools to access and modify information about spf records.  
//! Provides methods for building spf records programmatically.  
//!
//!
//! For a list of supported *Modifiers* and *Mechanism*. See [`Kind`]  
//!
//! This crate is able to deconstruct `v=spf1` and `spf2.0` records.
//!
//! # Abilities:
//! - Check and Set Spf record version. See: [`Spf Versions`](SpfBuilder::set_v1)
//! - Check and Create Spf Mechanism/Modifiers:
//!     - [`Mechanism`]
//!     - [`Mechanism Qualifier`](Mechanism::is_pass)
//!     - [`Mechanism Kind`](Mechanism::kind)
//!
//! # Feature Flags:
//! - `ptr` (Enabled by default.)  
//!    This feature will impact a future validation feature.
//! - `strict-dns` (Disabled by default.)  
//!   This enables syntactical checking of Domain Names.
//!     - When enabled it changes the behaviour of `FromStr` for `Mechanism<String>` and
//! `ParsedMechanism`. By default, `Mechanism<String>`'s `rrdata` is not checked.
//! - `spf2` (Disabled by default)  
//!   This enables the ability to programmatically create Spf2 (SenderID) records. As this
//!   has become defunct. There is no real need for it. But it remains as an option if desired.
//! - `serde` (Disabled by default.)
//!
mod core;
mod mechanism;
mod spf;

pub use crate::mechanism::{Kind, Mechanism, MechanismError, ParsedMechanism, Qualifier};
pub use crate::spf::{SpfBuilder, SpfError};
