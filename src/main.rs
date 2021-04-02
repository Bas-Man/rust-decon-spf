//use std::net::*;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::TxtLookup};
use trust_dns_resolver::{lookup::MxLookup, lookup::SoaLookup};

fn main() {
    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    // Lookup the IP addresses associated with a name.
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    let query = "hotmail.com.";

    let mx_response = resolver.mx_lookup(query);
    let soa_response = resolver.soa_lookup(query);
    let txt_response = resolver.txt_lookup(query);

    display_mx(&mx_response);
    display_soa(&soa_response);
    display_txt(&txt_response);
}
fn display_txt(txt_response: &ResolveResult<TxtLookup>) {
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                let my_txt = &record.to_string();
                println!("{}", my_txt);
                println!("");
                i = i + 1;
            }
        }
    }
}
fn display_soa(soa_response: &ResolveResult<SoaLookup>) {
    match soa_response {
        Err(_) => println!("No SOA."),
        Ok(soa_response) => {
            let soa_iter = soa_response.iter();
            for record in soa_iter {
                println!("Admin: {}", record.rname());
                let email = convert_rname_to_email_address(&record.rname().to_string());
                println!("Admin Email: {}", email);
                println!("Primary: {}", record.mname());
                println!("Serial: {}", record.serial());
            }
        }
    }
}
fn convert_rname_to_email_address(rname: &String) -> String {
    let rname = rname.clone();
    let mut email_address: String = String::new();
    let mut splitter = rname.splitn(2, ".");
    email_address.push_str(splitter.next().unwrap());
    email_address.push_str("@");
    email_address.push_str(splitter.next().unwrap());
    // Remove remaining period (.)
    email_address.pop();
    email_address
}
fn display_mx(mx_response: &ResolveResult<MxLookup>) {
    match mx_response {
        Err(_) => println!("No Records"),
        Ok(mx_response) => {
            let records = mx_response.iter();
            for record in records {
                println!("{} {}", record.preference(), record.exchange());
                let resolver =
                    Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
                let lookup_response = resolver.lookup_ip(record.exchange().to_string().as_str());
                match lookup_response {
                    Err(_) => println!("This exchange host has not address."),
                    Ok(lookup_response) => {
                        let ip_addrs = lookup_response.iter();
                        for ip_addr in ip_addrs {
                            if ip_addr.is_ipv4() {
                                println!("   ip4: {}", ip_addr)
                            } else {
                                println!("   ip6: {}", ip_addr)
                            }
                        }
                    }
                }
            }
        }
    }
}
