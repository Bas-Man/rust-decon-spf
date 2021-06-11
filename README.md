# Overview

This crate allows you to deconstruct an existing SPF record that might be retrieved with a dns query of type TXT.

An example program can be found in the **Examples** directory.
### Run example
To see a list of available examples.
```bash
$ cargo run --example
```

```bash
$ cargo run --example trust-dns-demo
```

## Syntax Validation

This crate is not intended to provide syntax validation.  
If you are looking to validate your SPF record. I would suggest you use one of the following.

1. [VamSoft.com](https://vamsoft.com/support/tools/spf-syntax-validator)
2. [Spf-Record.com](https://www.spf-record.com/analyzer)

I am sure there are many others that could be found.
