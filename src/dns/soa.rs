use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::lookup::SoaLookup;
pub fn display_soa(soa_response: &ResolveResult<SoaLookup>) {
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
