use ipnetwork::IpNetwork;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::MxLookup, lookup::SoaLookup, lookup::TxtLookup};

#[derive(Default, Debug, Clone)]
struct Includes {
    modifier: char,
    include_string: String,
}

impl Includes {
    fn new(modifier: char, include_string: String) -> Self {
        Self {
            modifier,
            include_string,
        }
    }
}

#[derive(Debug)]
struct Ip4 {
    modifier: char,
    ip: IpNetwork,
}

impl Ip4 {
    fn new(modifier: char, ip: IpNetwork) -> Self {
        Self { modifier, ip }
    }
}

impl Default for Ip4 {
    fn default() -> Self {
        Self {
            modifier: '+',
            ip: IpNetwork::V4("0.0.0.0/0".parse().unwrap()),
        }
    }
}

#[derive(Debug)]
struct Ip6 {
    modifier: char,
    ip: IpNetwork,
}

impl Ip6 {
    fn new(modifier: char, ip: IpNetwork) -> Self {
        Self { modifier, ip }
    }
}

impl Default for Ip6 {
    fn default() -> Self {
        Self {
            modifier: '+',
            ip: IpNetwork::V6("FE80::1".parse().unwrap()),
        }
    }
}

#[derive(Default, Debug)]
struct Spf1 {
    source: String,
    include: Option<Vec<Includes>>,
    redirect: Option<String>,
    is_redirected: bool,
    ip4: Option<Vec<Ip4>>,
    ip6: Option<Vec<Ip6>>,
    a: Option<Option<Vec<String>>>,
    mx: Option<Option<Vec<String>>>,
    all_modifier: char,
}

impl Spf1 {
    fn new(str: &String) -> Self {
        Self {
            source: str.clone(),
            include: None,
            redirect: None,
            is_redirected: false,
            ip4: None,
            ip6: None,
            a: None,
            mx: None,
            all_modifier: '+',
        }
    }
    fn parse(&mut self) {
        let records = self.source.split_whitespace();
        let mut vec_of_includes: Vec<Includes> = Vec::new();
        let mut vec_of_ip4: Vec<Ip4> = Vec::new();
        let mut vec_of_ip6: Vec<Ip6> = Vec::new();
        for record in records {
            // Check first character. Is it a Modifier (+,-,~,)
            if record.contains("redirect") {
                let items = record.rsplit("=");
                for item in items {
                    self.redirect = Some(item.to_string());
                    break;
                }
                self.is_redirected = true;
            } else if record.contains("include") {
                let modifier = return_modifier(record, 'i');
                let items = record.rsplit(":");
                for item in items {
                    vec_of_includes.push(Includes::new(modifier, item.to_string()));
                    break;
                }
            } else if record.contains("ip4") {
                let modifier = return_modifier(record, 'i');
                let ips = record.rsplit(":");
                for ip in ips {
                    let network: Ip4 = Ip4::new(modifier, ip.parse().unwrap());
                    vec_of_ip4.push(network);
                    break;
                }
            } else if record.contains("ip6") {
                // IP6 uses many ':' charcters. Normal split is difficult.
                // Also still needs to handle the case where "ip6:" is not the complete prefix.
                let modifier = return_modifier(record, 'i');
                if let Some(raw_ip6) = record.strip_prefix("ip6:") {
                    let network: Ip6 = Ip6::new(modifier, raw_ip6.parse().unwrap());
                    vec_of_ip6.push(network);
                }
            } else if record.ends_with("all") {
                self.all_modifier = return_modifier(record, 'a');
            }
        }
        if vec_of_includes.len() > 0 {
            self.include = Some(vec_of_includes);
        };
        if vec_of_ip4.len() > 0 {
            self.ip4 = Some(vec_of_ip4);
        };
        if vec_of_ip6.len() > 0 {
            self.ip6 = Some(vec_of_ip6);
        };
    }

    fn spf1(&self) -> String {
        self.source.clone()
    }

    fn list_of_includes(&self) -> Option<Vec<Includes>> {
        self.include.clone()
    }

    fn is_redirect(&self) -> bool {
        self.is_redirected
    }
}

fn return_modifier(record: &str, c: char) -> char {
    if c != record.chars().nth(0).unwrap() {
        record.chars().nth(0).unwrap()
    } else {
        '+'
    }
}

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
    let mut data = display_txt(&txt_response);
    data.parse();
    println!("{:?}", data);
    println!("SPF1: {}", data.spf1());
    println!("{:?}", data.list_of_includes());
    println!("Is a redirect: {}", data.is_redirect());
}

fn display_txt(txt_response: &ResolveResult<TxtLookup>) -> Spf1 {
    let mut data = Spf1::new(&"".to_string());
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                let my_txt = &record.to_string();
                println!("{}", my_txt);
                if my_txt.starts_with("v=spf1") {
                    data = Spf1::new(&my_txt.to_string());
                }
                println!("");
                i = i + 1;
            }
        }
    }
    data
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
