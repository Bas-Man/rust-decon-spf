use ipnetwork::IpNetwork;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::{config::*, lookup::MxLookup, lookup::SoaLookup, lookup::TxtLookup};

#[derive(Debug, Clone)]
enum MechanismKind {
    Include,
    Redirect,
    A,
    MX,
    IpV4,
    IpV6,
    All,
}

impl MechanismKind {
    /// Returns `true` if the mechanism_kind is [`Include`].
    fn is_include(&self) -> bool {
        matches!(self, Self::Include)
    }
    /// Returns `true` if the mechanism_kind is [`A`].
    fn is_a(&self) -> bool {
        matches!(self, Self::A)
    }

    /// Returns `true` if the mechanism_kind is [`MX`].
    fn is_mx(&self) -> bool {
        matches!(self, Self::MX)
    }

    /// Returns `true` if the mechanism_kind is [`IpV4`].
    fn is_ip_v4(&self) -> bool {
        matches!(self, Self::IpV4)
    }

    /// Returns `true` if the mechanism_kind is [`IpV6`].
    fn is_ip_v6(&self) -> bool {
        matches!(self, Self::IpV6)
    }

    /// Returns `true` if the mechanism_kind is [`All`].
    fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns `true` if the mechanism_kind is [`Redirect`].
    fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
}

impl Default for MechanismKind {
    fn default() -> Self {
        Self::Include
    }
}

#[derive(Debug, Clone)]
struct SpfMechanism<T> {
    kind: MechanismKind,
    qualifier: char,
    mechanism: T,
}

impl SpfMechanism<String> {
    fn new_include(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Include, qualifier, mechanism)
    }
    fn new_redirect(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::Redirect, qualifier, mechanism)
    }
    fn new_all(qualifier: char, mechanism: String) -> Self {
        SpfMechanism::new(MechanismKind::All, qualifier, mechanism)
    }
    fn as_mechanism(&self) -> String {
        // rebuild and return the string representation of a include, redirect, a or mx mechanism
        let mut txt = String::new();
        if self.qualifier != '+' {
            txt.push(self.qualifier);
        } else {
            // Do nothing omitting '+'
        }
        if self.kind.is_all() {
            txt.push_str("all")
        } else {
            txt.push_str(self.mechanism_prefix_from_kind().as_str());
            txt.push_str(self.mechanism.as_str());
        }
        txt
    }
    fn as_string(&self) -> &String {
        &self.mechanism
    }
}
impl SpfMechanism<IpNetwork> {
    fn new_ip4(qualifier: char, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV4, qualifier, mechanism)
    }
    fn new_ip6(qualifier: char, mechanism: IpNetwork) -> Self {
        SpfMechanism::new(MechanismKind::IpV6, qualifier, mechanism)
    }
    fn as_mechanism(&self) -> String {
        // rebuild and return the string represensation of a include, redirect mechanism
        let mut txt = String::new();
        if self.qualifier != '+' {
            txt.push(self.qualifier);
        } else {
            // Do nothing omitting '+'
        }
        txt.push_str(self.mechanism_prefix_from_kind().as_str());
        txt.push_str(self.mechanism.to_string().as_str());
        txt
    }
    fn as_string(&self) -> String {
        self.mechanism.to_string()
    }
}
impl<T> SpfMechanism<T> {
    fn new(kind: MechanismKind, qualifier: char, mechanism: T) -> Self {
        Self {
            kind,
            qualifier,
            mechanism,
        }
    }
    fn is_pass(&self) -> bool {
        self.qualifier == '+'
    }
    fn is_fail(&self) -> bool {
        self.qualifier == '-'
    }
    fn is_softfail(&self) -> bool {
        self.qualifier == '~'
    }
    fn is_neutral(&self) -> bool {
        self.qualifier == '?'
    }
    fn mechanism_prefix_from_kind(&self) -> String {
        let push_str = match self.kind {
            MechanismKind::Redirect => "redirect=",
            MechanismKind::Include => "include:",
            MechanismKind::A => "a:",   // requires modification
            MechanismKind::MX => "mx:", // requires modication
            MechanismKind::IpV4 => "ip4:",
            MechanismKind::IpV6 => "ip6:",
            MechanismKind::All => "",
        };
        push_str.to_string()
    }
}

#[derive(Default, Debug)]
struct Spf1 {
    source: String,
    include: Option<Vec<SpfMechanism<String>>>,
    redirect: Option<SpfMechanism<String>>,
    is_redirected: bool,
    a: Option<Vec<SpfMechanism<String>>>,
    mx: Option<Vec<SpfMechanism<String>>>,
    ip4: Option<Vec<SpfMechanism<IpNetwork>>>,
    ip6: Option<Vec<SpfMechanism<IpNetwork>>>,
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
        // initialises required variables.
        let records = self.source.split_whitespace();
        let mut vec_of_includes: Vec<SpfMechanism<String>> = Vec::new();
        let mut vec_of_ip4: Vec<SpfMechanism<IpNetwork>> = Vec::new();
        let mut vec_of_ip6: Vec<SpfMechanism<IpNetwork>> = Vec::new();
        //let mut vec_of_a: Vec<A> = Vec::new();
        //let mut vec_of_mx: Vec<A> = Vec::new();
        for record in records {
            if record.contains("redirect=") {
                // Match a redirect
                let items = record.rsplit("=");
                for item in items {
                    self.redirect = Some(SpfMechanism::new_redirect('+', item.to_string()));
                    break;
                }
                self.is_redirected = true;
            } else if record.contains("include:") {
                // Match an include
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                for item in record.rsplit(":") {
                    vec_of_includes.push(SpfMechanism::new_include(
                        qualifier_and_modified_str.0,
                        item.to_string(),
                    ));
                    break; // skip the 'include:'
                }
            } else if record.contains("ip4:") {
                // Match an ip4
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip4) = qualifier_and_modified_str.1.strip_prefix("ip4:") {
                    let network = SpfMechanism::new_ip4(
                        qualifier_and_modified_str.0,
                        raw_ip4.parse().unwrap(),
                    );
                    vec_of_ip4.push(network);
                }
            } else if record.contains("ip6:") {
                // Match an ip6
                let qualifier_and_modified_str = return_and_remove_qualifier(record, 'i');
                if let Some(raw_ip6) = qualifier_and_modified_str.1.strip_prefix("ip6:") {
                    let network = SpfMechanism::new_ip6(
                        qualifier_and_modified_str.0,
                        raw_ip6.parse().unwrap(),
                    );
                    vec_of_ip6.push(network);
                }
            } else if record.ends_with("all") {
                // deal with all if present
                self.all_qualifier = return_and_remove_qualifier(record, 'a').0;
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

    fn source(&self) -> &String {
        &self.source
    }
    fn clone(&self) -> &Spf1 {
        self.clone()
    }

    fn includes(&self) -> Option<Vec<SpfMechanism<String>>> {
        self.include.clone()
    }
    fn list_includes(&self) {
        match &self.include {
            None => println!("There are no include elements"),
            Some(elements) => {
                println!("Include Mechanisms:");
                for element in elements {
                    println!("{}", element.as_mechanism());
                }
            }
        }
    }
    fn ip4(&self) -> Option<Vec<SpfMechanism<IpNetwork>>> {
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
    fn ip4_mechanisms(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 spf records."),
            Some(records) => {
                println!("\nList of ip4 mechanisms:");
                for record in records {
                    println!("{}", record.as_mechanism())
                }
            }
        }
    }
    fn ip6(&self) -> Option<Vec<SpfMechanism<IpNetwork>>> {
        self.ip6.clone()
    }
    fn ip6_networks(&self) {
        match &self.ip6 {
            None => println!("There are no ip6 networks"),
            Some(record) => {
                println!("List of ip6 networks/hosts:");
                for item in record {
                    println!("{}", item.as_string());
                }
            }
        }
    }
    fn ip6_mechanisms(&self) {
        match &self.ip6 {
            None => println!("There are no ip6 spf records."),
            Some(records) => {
                println!("\nList of ip6 mechanisms:");
                for record in records {
                    println!("{}", record.as_mechanism())
                }
            }
        }
    }

    fn is_redirect(&self) -> bool {
        self.is_redirected
    }
    fn redirect(&self) -> String {
        self.redirect.as_ref().unwrap().as_string().to_string()
    }
    fn redirect_as_mechanism(&self) -> Option<String> {
        if self.is_redirect() {
            Some(self.redirect.as_ref().unwrap().as_mechanism())
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
    // Remove leading (+,-,~,?) character and return an updated str
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

fn display_txt(query: &str, txt_response: &ResolveResult<TxtLookup>) -> Spf1 {
    let mut data = Spf1::default();
    match txt_response {
        Err(_) => println!("No TXT Records."),
        Ok(txt_response) => {
            let mut i = 1;
            println!("List of TXT records found for {}", &query);
            for record in txt_response.iter() {
                println!("TXT Record {}:", i);
                println!("{}", &record.to_string());
                if record.to_string().starts_with("v=spf1") {
                    data = Spf1::new(&record.to_string());
                }
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
