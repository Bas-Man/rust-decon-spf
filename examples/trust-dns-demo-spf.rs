use decon_spf::Spf;
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

    let spf_record = display_txt(&query, &txt_response);
    println!("\nDeconstructing SPF Record");
    println!("Debug Output!");
    println!("{:?}", spf_record);
    println!("\nSource Attribute Output");
    println!("SPF1: {}\n", spf_record.to_string());
    /*
    if spf_record.includes().is_some() {
        println!("Include list");
        for mechanism in spf_record.includes().unwrap().iter() {
            println!("spf: {}", mechanism);
        }
    }
    if let Some(list) = spf_record.ip4() {
        println!("IP4 Address Ranges");
        for mechanism in list.iter() {
            println!(
                "Network: {} prefix: {}",
                mechanism.as_network().network(),
                mechanism.as_network().prefix()
            );
            println!("Mechanism: {}", mechanism);
        }
    }
    if let Some(list) = spf_record.ip6() {
        println!("IP6 Address Ranges");
        for mechanism in list.iter() {
            println!(
                "Network: {} prefix: {}",
                mechanism.as_network().network(),
                mechanism.as_network().prefix()
            );
            println!("spf: {}", mechanism);
        }
    }
    println!("\nIs a redirect: {}", spf_record.is_redirect());
    if spf_record.is_redirect() {
        if let Some(mechanism) = spf_record.redirect() {
            println!("\nRaw Redirect: {}", mechanism.raw());
            println!("Mechanism: {}", mechanism);
        }
    }
    println!("Build Spf from Struct. Not from source()");
    println!("Spf: {}", spf_record);

     */
}

fn display_txt(query: &str, txt_response: &ResolveResult<TxtLookup>) -> Spf<String> {
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
                    spf_record = record.to_string().parse().unwrap();
                }
                i = i + 1;
            }
        }
    }
    spf_record
}
