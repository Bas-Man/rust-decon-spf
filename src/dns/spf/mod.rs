pub mod kinds;
pub mod mechanism;

use crate::dns::spf::mechanism::SpfMechanism;
use ipnetwork::IpNetwork;

#[derive(Default, Debug)]
pub struct Spf {
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

impl Spf {
    pub fn new(str: &String) -> Self {
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
    pub fn parse(&mut self) {
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
        if !vec_of_includes.is_empty() {
            self.include = Some(vec_of_includes);
        };
        if !vec_of_ip4.is_empty() {
            self.ip4 = Some(vec_of_ip4);
        };
        if !vec_of_ip6.is_empty() {
            self.ip6 = Some(vec_of_ip6);
        };
    }

    pub fn source(&self) -> &String {
        &self.source
    }
    pub fn spf_clone(&self) -> &Spf {
        self.clone()
    }

    pub fn includes(&self) -> &Option<Vec<SpfMechanism<String>>> {
        &self.include
    }
    pub fn list_includes(&self) {
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
    pub fn ip4(&self) -> &Option<Vec<SpfMechanism<IpNetwork>>> {
        &self.ip4
    }
    pub fn ip4_networks(&self) {
        match &self.ip4 {
            None => println!("There are no ip4 networks"),
            Some(record) => {
                println!("List of ip4 networks/hosts:");
                for item in record {
                    println!("{}", item.as_string());
                    print!("Network: {}", item.as_network().network());
                    println!(" Subnet: {}", item.as_network().prefix());
                }
            }
        }
    }
    pub fn ip4_mechanisms(&self) {
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
    pub fn ip6(&self) -> &Option<Vec<SpfMechanism<IpNetwork>>> {
        &self.ip6
    }
    pub fn ip6_networks(&self) {
        match &self.ip6 {
            None => println!("There are no ip6 networks"),
            Some(record) => {
                println!("List of ip6 networks/hosts:");
                for item in record {
                    println!("{}", item.as_string());
                    print!("Network: {}", item.as_network().network());
                    println!(" Subnet: {}", item.as_network().prefix());
                }
            }
        }
    }
    pub fn ip6_mechanisms(&self) {
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

    pub fn is_redirect(&self) -> bool {
        self.is_redirected
    }
    pub fn redirect(&self) -> String {
        self.redirect.as_ref().unwrap().as_string().to_string()
    }
    pub fn redirect_as_mechanism(&self) -> Option<String> {
        if self.is_redirect() {
            Some(self.redirect.as_ref()?.as_mechanism())
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
