# Overview

This crate allows you to deconstruct an existing SPF record that might be retrieved with a dns query of type TXT.  

With 0.2.0. You now have the ability to create SPF records programmatically. 
Check the **Examples** directory for sample code.

### See Example Code

Lookup and deconstruct Spf record.

- [trust-dns-resolver](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/trust-dns-resolver.rs)
- [build-spf](https://github.com/Bas-Man/rust-decon-spf/blob/master/examples/build-new-spf.rs)

### Run example
To see a list of available examples.
```bash
$ cargo run --example
```

```bash
$ cargo run --example trust-dns-demo
$ cargo run --example build-spf
```

## Syntax Validation

This crate is not intended to provide syntax validation.  
If you are looking to validate your SPF record. I would suggest you use one of the following.

1. [VamSoft.com](https://vamsoft.com/support/tools/spf-syntax-validator)
2. [Spf-Record.com](https://www.spf-record.com/analyzer)

I am sure there are many others that could be found.
