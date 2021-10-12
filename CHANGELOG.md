0.2.0 DATE
==========

- Bump Version to 0.2.0
- Correct license reference to correctly show as MIT license
- Add this CHANGELOG.md file.
- Introduce ability to build SPF records programmatically. 
  - See examples/build-new-spf.rs
- Implement **Display** trait for structs *Spf* and *Mechanism*
  - This also deprecates the previously implement *string()* methods.
