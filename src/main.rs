use ipnetwork::IpNetwork;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::MxLookup, lookup::SoaLookup, lookup::TxtLookup};

#[derive(Default, Debug, Clone)]
struct Includes {
    qualifier: char,
    txt: String,
}

impl Includes {
    fn new(qualifier: char, txt: String) -> Self {
        Self { qualifier, txt }
    }
    fn as_string(&self) -> String {
        let mut txt = String::new();
        if self.qualifier != '+' {
            txt.push(self.qualifier);
        }
        txt.push_str("include:");
        txt.push_str(self.txt.as_str());
        txt
    }
    fn is_pass(&self) -> bool {
        if self.qualifier == '+' {
            true
        } else {
            false
        }
    }
    fn is_fail(&self) -> bool {
        if self.qualifier == '-' {
            true
        } else {
            false
        }
    }
    fn is_softfail(&self) -> bool {
        if self.qualifier == '~' {
            true
        } else {
            false
        }
    }
    fn is_neutral(&self) -> bool {
        if self.qualifier == '?' {
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct A {
    qualifier: char,
    txt: String,
}

impl A {
    fn new(qualifier: char, txt: String) -> Self {
        Self { qualifier, txt }
    }
}

#[derive(Debug, Clone)]
struct Mx {
    qualifier: char,
    txt: String,
}

impl Mx {
    fn new(qualifier: char, txt: String) -> Self {
        Self { qualifier, txt }
    }
}

#[derive(Debug, Clone)]
struct Ip4 {
    qualifier: char,
    ip: IpNetwork,
}

impl Ip4 {
    fn new(qualifier: char, ip: IpNetwork) -> Self {
        Self { qualifier, ip }
    }
    fn as_string(&self) -> String {
        self.ip.to_string()
    }
    fn as_spf(&self) -> String {
        let mut ip4_string = String::new();
        if self.qualifier != '+' {
            ip4_string.push(self.qualifier);
        }
        ip4_string.push_str("ip4:");
        ip4_string.push_str(self.ip.to_string().as_str());
        ip4_string
    }
    fn as_ip(&self) -> IpNetwork {
        self.ip
    }
    fn is_pass(&self) -> bool {
        if self.qualifier == '+' {
            true
        } else {
            false
        }
    }
    fn is_fail(&self) -> bool {
        if self.qualifier == '-' {
            true
        } else {
            false
        }
    }
    fn is_softfail(&self) -> bool {
        if self.qualifier == '~' {
            true
        } else {
            false
        }
    }
    fn is_neutral(&self) -> bool {
        if self.qualifier == '?' {
            true
        } else {
            false
        }
    }
}

impl Default for Ip4 {
    fn default() -> Self {
        Self {
            qualifier: '+',
            ip: IpNetwork::V4("0.0.0.0/0".parse().unwrap()),
        }
    }
}

#[derive(Debug, Clone)]
struct Ip6 {
    qualifier: char,
    ip: IpNetwork,
}

impl Ip6 {
    fn new(qualifier: char, ip: IpNetwork) -> Self {
        Self { qualifier, ip }
    }
}

impl Default for Ip6 {
    fn default() -> Self {
        Self {
            qualifier: '+',
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
    a: Option<Vec<A>>,
    mx: Option<Vec<Mx>>,
    ip4: Option<Vec<Ip4>>,
    ip6: Option<Vec<Ip6>>,
    all_qualifier: char,
}

impl Spf1 {
    fn new(str: &String) -> Self {
        Self {
            source: str.clone(),
            include: None,
            redirect: None,
            is_redirected: false,
            a: None,
            mx: None,
            ip4: None,
            ip6: None,
            all_qualifier: '+',
        }
    }
    fn parse(&mut self) {
        let records = self.source.split_whitespace();
        let mut vec_of_includes: Vec<Includes> = Vec::new();
        let mut vec_of_ip4: Vec<Ip4> = Vec::new();
        let mut vec_of_ip6: Vec<Ip6> = Vec::new();
        //let mut vec_of_a: Vec<A> = Vec::new();
        //let mut vec_of_mx: Vec<A> = Vec::new();
        for record in records {
            if record.contains("redirect") {
                let items = record.rsplit("=");
                for item in items {
                    self.redirect = Some(item.to_string());
                    break;
                }
                self.is_redirected = true;
            } else if record.contains("include:") {
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                for item in record.rsplit(":") {
                    vec_of_includes.push(Includes::new(
                        qualifier_and_modified_str.0,
                        item.to_string(),
                    ));
                    break; // skip the 'include:'
                }
            } else if record.contains("ip4:") {
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip4) = qualifier_and_modified_str.1.strip_prefix("ip4:") {
                    let network: Ip4 =
                        Ip4::new(qualifier_and_modified_str.0, raw_ip4.parse().unwrap());
                    vec_of_ip4.push(network);
                }
            } else if record.contains("ip6:") {
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip6) = qualifier_and_modified_str.1.strip_prefix("ip6:") {
                    let network: Ip6 =
                        Ip6::new(qualifier_and_modified_str.0, raw_ip6.parse().unwrap());
                    vec_of_ip6.push(network);
                }
            } else if record.ends_with("all") {
                self.all_qualifier = return_and_remove_qualifier(record, 'a').0;
            }
        }
        //if vec_of_a.len() > 0 {
        //    self.a = Some(vec_of_a);
        //}
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

    fn spf_source(&self) -> &String {
        &self.source
    }
    fn clone_spf(&self) -> &Spf1 {
        self.clone()
    }

    fn includes(&self) -> Option<Vec<Includes>> {
        self.include.clone()
    }
    fn list_includes(&self) {
        match &self.include {
            None => println!("There are no include elements"),
            Some(elements) => {
                println!("Include Elements:");
                for element in elements {
                    println!("{}", element.as_string());
                }
            }
        }
    }
    fn ip4(&self) -> Option<Vec<Ip4>> {
        self.ip4.clone()
    }
    fn ip4_networks(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 networks"),
            Some(record) => {
                println!("List of ip4 networks/hosts:");
                for item in record {
                    println!("{}", item.as_string());
                }
            }
        }
    }
    fn ip4_spf_strings(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 spf records."),
            Some(records) => {
                println!("List of spf ip4 records:");
                for record in records {
                    println!("{}", record.as_spf())
                }
            }
        }
    }
    fn ip6(&self) -> Option<Vec<Ip6>> {
        self.ip6.clone()
    }

    fn is_redirect(&self) -> bool {
        self.is_redirected
    }
    fn redirect(&self) -> String {
        if self.is_redirect() {
            self.redirect.as_ref().unwrap().to_string()
        } else {
            String::from("")
        }
    }
    fn redirect_as_spf(&self) -> Option<String> {
        if self.is_redirect() {
            let mut txt = String::new();
            txt.push_str("redirect:");
            txt.push_str(self.redirect.as_ref().unwrap().as_str());
            Some(txt)
        } else {
            None
        }
    }
}

// Check if the initial character in the string `record` matches `c`
// If they do no match then return the initial character
// if c matches first character of record, we can `+`, a blank modiifer equates to `+`
fn return_and_remove_qualifier(record: &str, c: char) -> (char, &str) {
    // Returns a tuple of (qualifier, &str)
    // &str will have had the qualifier character removed if it existed. The &str will be unchanged
    // if the qualifier was not present
    if c != record.chars().nth(0).unwrap() {
        // qualifier exists. return tuple of qualifier and `record` with qualifier removed.
        (record.chars().nth(0).unwrap(), remove_qualifier(record))
    } else {
        // qualifier does not exist, default to `+` and return unmodified `record`
        ('+', record)
    }
}
fn remove_qualifier(record: &str) -> &str {
    // Remove leading (+,-,~,?) character
    let mut chars = record.chars();
    chars.next();
    chars.as_str()
}

fn main() {
    // Construct a new Resolver with default configuration options
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    // Lookup the IP addresses associated with a name.
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    //let response = resolver.lookup_ip("example.com.").unwrap();
    let query = "hotmail.com.";
    //let mx_response = resolver.mx_lookup(query);
    //let soa_response = resolver.soa_lookup(query);
    let txt_response = resolver.txt_lookup(query);

    //display_mx(&mx_response);
    //display_soa(&soa_response);
    let mut data = display_txt(&txt_response);
    data.parse();
    println!("{:?}", data);
    println!("SPF1: {}", data.spf_source());
    println!("{:?}", data.includes());
    data.list_includes();
    data.ip4_networks();
    data.ip4_spf_strings();
    println!("Is a redirect: {}", data.is_redirect());
    if data.is_redirect() {
        println!("redirect: {}", data.redirect());
        println!(
            "{}",
            data.redirect_as_spf()
                .unwrap_or("Not a redirect.".to_string())
        );
    }
}

fn display_txt(txt_response: &ResolveResult<TxtLookup>) -> Spf1 {
    let mut data = Spf1::default();
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                println!("{}", &record.to_string());
                if record.to_string().starts_with("v=spf1") {
                    data = Spf1::new(&record.to_string());
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
