# Overview

This crate allows you to deconstruct an existing SPF record that might be retrieved with a dns query of type TXT.  

With 0.2.0. You now have the ability to create SPF records programmatically. Check in the **Examples** directory for sample code.

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

    // This is a list of servers you can test the code against. Feel free to edit
    // the query

    let query = "gmail.com.";
    //let query = "hotmail.com.";
    //let query = "_netblocks.google.com."; // ip4
    //let query = "_netblocks2.google.com."; // ip6

    let txt_response = resolver.txt_lookup(query);

    let mut spf_record = display_txt(&query, &txt_response);
    println!("\nDecontructing SPF Record");
    let _ = spf_record.parse();
    println!("{:?}", spf_record);
    println!("SPF1: {}\n", spf_record.source());
    if spf_record.includes().is_some() {
        println!("Include list");
        for mechanism in spf_record.includes().unwrap().iter() {
            println!("spf: {}", mechanism.string());
        }
    }
    if spf_record.ip4().is_some() {
        println!("IP4 Address Ranges");
        for mechanism in spf_record.ip4().unwrap().iter() {
            println!(
                "IP: {} prefix: {}",
                mechanism.as_network().network(),
                mechanism.as_network().prefix()
            );
            println!("spf: {}", mechanism.string());
        }
    }
    if spf_record.ip6().is_some() {
        println!("IP6 Address Ranges");
        for mechanism in spf_record.ip6().unwrap().iter() {
            println!(
                "IP: {} prefix: {}",
                mechanism.as_network().network(),
                mechanism.as_network().prefix()
            );
            println!("spf: {}", mechanism.string());
        }
    }
    println!("\nIs a redirect: {}", spf_record.is_redirect());
    if spf_record.is_redirect() {
        println!("\nredirect: {}", spf_record.redirect().unwrap().raw());
        println!("mechanism: {}", spf_record.redirect().unwrap().string());
    }
}

fn display_txt(query: &str, txt_response: &ResolveResult<TxtLookup>) -> Spf {
    let mut spf_record = Spf::default();
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            println!("List of TXT records found for {}", &query);
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                println!("{}", &record.to_string());
                if record.to_string().starts_with("v=spf1") {
                    spf_record = Spf::from_str(&record.to_string());
                }
                i = i + 1;
            }
        }
    }
    spf_record
}
```

### Run example
To see a list of available examples.
```bash
$ cargo run --example
```

```bash
$ cargo run --example trust-dns-demo
$ cargo run --example build-new-spf.rs
```

## Syntax Validation

This crate is not intended to provide syntax validation.  
If you are looking to validate your SPF record. I would suggest you use one of the following.

1. [VamSoft.com](https://vamsoft.com/support/tools/spf-syntax-validator)
2. [Spf-Record.com](https://www.spf-record.com/analyzer)

I am sure there are many others that could be found.
