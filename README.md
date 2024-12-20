[![Latest Version](https://img.shields.io/crates/v/decon-spf.svg)](https://crates.io/crates/decon-spf) [![Docs](https://docs.rs/decon-spf/badge.svg)](https://docs.rs/decon-spf)

# Overview

This crate allows you to deconstruct an existing SPF record that might be retrieved with a dns query of type TXT.

With 0.2.0. You now have the ability to create SPF records programmatically.
Check the **Examples** directory for sample code.

### See Example Code

Lookup and deconstruct Spf record.

- [trust-dns-resolver-builder](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/trust-dns-demo-builder.rs)
- [trust-dns-resolver-spf](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/trust-dns-demo-spf.rs)
- [build-spf](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/build-spf.rs)
- [build-spf-strict](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/build-spf-strict.rs)
- [serde-demo](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/serde-demo.rs)

### Run example

To see a list of available examples.

```bash
$ cargo run --example
```

```bash
$ cargo run --example trust-dns-builder
$ cargo run --example trust-dns-spf
$ cargo run --example build-spf
$ cargo run -F strict-dns --example build-spf-strict
$ cargo run -F serde --example serde-demo
```

## Syntax Validation

Whilst this crate is not intended to provide syntax validation, some validation has been added as
of Version **0.3.0**.  
If you are looking to validate your SPF record. I would suggest you use one of
the following:

1. [VamSoft.com](https://vamsoft.com/support/tools/spf-syntax-validator)
2. [Spf-Record.com](https://www.spf-record.com/analyzer)

I am sure there are many others that could be found.
