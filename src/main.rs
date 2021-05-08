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
    let query = "gmail.com.";
    //let mx_response = resolver.mx_lookup(query);
    //let soa_response = resolver.soa_lookup(query);
    let txt_response = resolver.txt_lookup(query);

    //display_mx(&mx_response);
    //display_soa(&soa_response);
    let mut data = display_txt(&query, &txt_response);
    println!("\nDecontructing SPF Record");
    data.parse();
    println!("{:?}", data);
    println!("SPF1: {}\n", data.source());
    //println!("{:?}", data.includes());
    data.list_includes();
    data.ip4_networks();
    data.ip4_mechanisms();
    data.ip6_networks();
    data.ip6_mechanisms();
    println!("\nIs a redirect: {}", data.is_redirect());
    if data.is_redirect() {
        println!("\nredirect: {}", data.redirect());
        println!(
            "mechanism: {}",
            data.redirect_as_mechanism()
                .unwrap_or("Not a redirect.".to_string())
        );
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
                    data = Spf::new(&record.to_string());
                }
                i = i + 1;
            }
        }
    }
    data
}
