#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! The deconf-spf crate is responsible for providing tooks to access and modify information about spf records
//! that have been parsed.  
//! It provides the ability to access information about Spf mechanisms.  
//! Provides methods for building spf records programmatically.  
//!
//! # Example
//! The ability to check what version of the Spf record was specified as:
//!
//! - *v=spf1* or *spf2.0/* using `is_v1()` or `is_v2()`
//!
//! Check if the spf record is a *redirect*
//!
//! - `is_redirect()`
//!
//! For any given mechanism we can:
//! - check its *Qualifier* status
//!     - `is_pass()`, `is_fail()`, `is_softfail()`, `is_neutral()`
//!
//! - Check its *Kind*
//!     - `kind().is_a()`, `kind().is_mx()` and more.
//!
//! For **IP4/6** we can access it as an [IpNetwork](mechanism::Mechanism::as_network())
//! as well as access its [String]mechanism::Mechanism<IpNetwork>::string()) representation.
//!
//! See [mechanism::Mechanism].
//!
#[doc(hidden)]
pub mod helpers;
pub mod mechanism;
pub mod spf;
