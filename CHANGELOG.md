0.3.2 2024-12-07
================

- Add
    - spf.lookup_count()\
      `Spf<String>` now contain the number of lookup that will be needed given
      its definition.
    - Tests and serde checks updated.
    - For informative documentation for spf.validate() also added.

0.3.1 2024-12-06
================

- Fix
    - TryFrom `Spf<String>` to SpfBuilder\
      The original code was actually incomplete. This has been corrected
      and tests have been added.

        - Note: TryFrom traits\
          The `TryFrom` trait was used for any `Mechanism<String>` as these have the
          potential to fail if an incorrect `Mechanism<T>` is passed.\

          Example:\
          "mx" is a `Mechanism<String>` and can not be converted to `Mechanism<IpNetwork>`
        -

0.3.0 2024-12-03
================

- Breaking Changes
    - `Spf` struct renamed to `SpfBuilder` and placed behind a `builder` flag.
    - New simplified `Spf<T>` struct defined.
    - New Spf<String> Implementation.

___

- Add

    - `iter()` functionality for `Spf` & `SpfBuilder`
    - `From` implementations
        - From `Mechanism<IpNetwork>` for `Mechanism<String>`
        - From `Mechanism<All>` for `Mechanism<String>`
        - From `Spf<String>` for `SpfBuilder`
    - `trait Appendable`
        - This provides a dynamically dispatched `append()` function that accepts
          either a `Mechanism<String>` or `Mechanism<IpNetwork>`
    - `validate()` for `Spf<String>`
        - This function returns either `()` or a `SpfErrors`

- Fix

    - `Mechanism<IpNetwork>`
        - This Mechanism now correctly returns IP Addresses and Networks.
          Previously `ip4:192.168.1.10` would later be returned as `ip4:192.168.1.10/32`.
          This has now been corrected for both ip4 and ip6.

___

0.2.6 2023-12-18
================

- Add Serialize and Deserialize Support
    - Requires the serde feature to be enabled.

0.2.5 2023-11-04
================

- Add support to Mechanism `exist` for Macro Expansion. Strings starting with `%` will now be matched.
  Support contributed by [22ca54d00f05391d6ffee4bc23a5ba60](phttps://github.com/22ca54d00f05391d6ffeoe4bc23a5ba60)

0.2.4 2022-01-19
================

- Remove code which has been deprecated since 0.2.0
- Implement `strict-dns` feature
    - Use crate `addr` to validate *domain* information for `a`, `mx`, `ptr`, `include`, and `exists`
    - See: `examples/build-spf-strict.rs`
- Deprecate `Mechanism::new_` functions.
- Breaking Change: Rename some `MechanismError::` messages.

0.2.3 2021-12-09
================

- Add `#[cfg(feature = warn-dns)]` to code documentation to remove warnings and errors when feature is not enabled.

0.2.2 2021-12-09
================

- Add Feature (warn-dns)  
  With this feature enabled any malformed DNS records will cause `has_warnings()` to be set to `true`. Their values can
  then be accessed using `warnings()`. Even though they are invalid. No error will be generated.

0.2.1 2021-11-03
================

- Documentation Update

0.2.0 2021-11-02
================

Breaking Changes.
================================================================

- as_spf() removed. Replaced with a *Display* trait. Use `to_string()`
- .parse() removed. Replaced with *FromStr* trait. Use `parse::<Spf>()`

Changes
=======

- Bump Version to 0.2.0
- Add this CHANGELOG.md file.
- Complete re-orginisation of the crate's module layout.
    - Note that spf::{qualifier::Qualifier, kinds::MechanismKind, mechanism::Mechanism} no longer exist. These can now
      be accessed more simply as:
        - mechanism::{Qualifer, Kind, Mechanism}
- Correct license reference to correctly show as MIT license
- Introduced ability to build SPF records programmatically.
    - See examples/build-new-spf.rs
- Implemented **Display** trait for structs *Spf* and *Mechanism*
    - This also depreciates the previously implemented *as_spf()* and *string()* methods.
- implemented **FromStr** trait for Struct *Spf*
- Implemented Errors for `Mechanism`
- Improved regular expressions to handle more strings when parsing.
