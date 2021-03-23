//use std::net::*;
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

fn main() {
    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    // Lookup the IP addresses associated with a name.
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    //let response = resolver.lookup_ip("example.com.").unwrap();
    let mx_response = resolver.mx_lookup("hotmail.com.");

    // There can be many addresses associated with the name,
    //  this can return IPv4 and/or IPv6 addresses
    //let address = response.iter().next().expect("no addresses returned!");
    //println!("{}", address);

    match mx_response {
        Err(_) => println!("No Records"),
        Ok(mx_response) => {
            let addresses = mx_response.iter();
            for record in addresses {
                println!("{} {}", record.preference(), record.exchange());
                let host_name = record.exchange();
                let lookup_response = resolver.lookup_ip(host_name.to_string().as_str()).unwrap();
                let addr_list = lookup_response.iter();
                for addr in addr_list {
                    if addr.is_ipv4() {
                        println!("\tip4: {}", addr)
                    } else {
                        println!("\tip6: {}", addr)
                    }
                }
            }
        }
    }
    //if address.is_ipv4() {
    //    println!("test");
    //    assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    //} else {
    //    println!("test2");
    //    assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
    //}
}
