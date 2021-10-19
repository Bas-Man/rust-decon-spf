0.2.0 DATE
==========

Breaking Changes.
================================================================

- as_spf() removed. Replaced with a *Display* trait. Use `to_string()`

Changes
=======

- Bump Version to 0.2.0
- Add this CHANGELOG.md file.
- Complete re-orginisation of the crate's module layout.
  - Note that spf::{qualifier::Qualifer, kinds::MechanismKind, mechanism::Mechanism} no longer exist. These can now be accessed more simply as: 
    -  mechanism::{Qualifer, Kind, Mechanism} 
- Correct license reference to correctly show as MIT license
- Introduce ability to build SPF records programmatically. 
  - See examples/build-new-spf.rs
- Implement **Display** trait for structs *Spf* and *Mechanism*
  - This also depreciates the previously implemented *as_spf()* and *string()* methods.
