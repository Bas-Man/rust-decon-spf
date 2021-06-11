# Overview

This crate allows you to deconstruct an existing SPF record that might be retrieved with a dns query of type TXT.

An example program can be found in the **Examples** directory.
### Example Code
```rust
use decon_spf::spf::Spf;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::TxtLookup};

fn main() {
    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    // Lookup the IP addresses associated with a name.
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    //let response = resolver.lookup_ip("example.com.").unwrap();

    //let query = "gmail.com.";
    let query = "hotmail.com.";
    //let query = "_netblocks.google.com."; // ip4
    //let query = "_netblocks2.google.com."; // ip6

    let txt_response = resolver.txt_lookup(query);

    let mut data = display_txt(&query, &txt_response);
    println!("\nDecontructing SPF Record");
    data.parse();
    println!("{:?}", data);
    println!("SPF1: {}\n", data.source());
    if data.includes().is_some() {
        println!("Include list");
        for i in data.includes().unwrap().iter() {
            println!("spf: {}", i.string());
        }
    }
    if data.ip4().is_some() {
        println!("IP4 Address Ranges");
        for i in data.ip4().unwrap().iter() {
            println!(
                "IP: {} prefix: {}",
                i.as_network().network(),
                i.as_network().prefix()
            );
            println!("spf: {}", i.string());
        }
    }
    if data.ip6().is_some() {
        println!("IP6 Address Ranges");
        for i in data.ip6().unwrap().iter() {
            println!(
                "IP: {} prefix: {}",
                i.as_network().network(),
                i.as_network().prefix()
            );
            println!("spf: {}", i.string());
        }
    }
    println!("\nIs a redirect: {}", data.is_redirect());
    if data.is_redirect() {
        println!("\nredirect: {}", data.redirect().unwrap().raw());
        println!("mechanism: {}", data.redirect().unwrap().string());
    }
}

fn display_txt(query: &str, txt_response: &ResolveResult<TxtLookup>) -> Spf {
    let mut data = Spf::default();
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            println!("List of TXT records found for {}", &query);
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                println!("{}", &record.to_string());
                if record.to_string().starts_with("v=spf1") {
                    data = Spf::from_str(&record.to_string());
                }
                i = i + 1;
            }
        }
    }
    data
}
```

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
