use decon_spf::SpfBuilder;
use decon_spf::{Mechanism, ParsedMechanism, Qualifier};
use serde_json;

fn main() {
    let mut spf1 = SpfBuilder::new();
    spf1.set_v1();
    let ip_m_1 = ParsedMechanism::new("ip4:203.32.160.0/24");
    let ip_m_2 = ParsedMechanism::new("+ip4:203.32.166.0/24");
    let mx = ParsedMechanism::new("mx").unwrap();
    if let Ok(ip1) = ip_m_1 {
        spf1.append_mechanism(ip1.network());
    }
    if let Ok(ip2) = ip_m_2 {
        spf1.append_mechanism(ip2.network());
    }
    spf1.append_mechanism(mx.txt());

    spf1.append_mechanism("a:test.com".parse::<Mechanism<String>>().unwrap());

    println!("New spf 1: >{}<", spf1);
    assert_eq!(
        spf1.to_string(),
        "v=spf1 a:test.com mx ip4:203.32.160.0/24 ip4:203.32.166.0/24"
    );

    let spf_as_json = serde_json::to_string_pretty(&spf1).unwrap();
    println!("JSON:\n{}", spf_as_json);

    let mut spf2 = SpfBuilder::new();
    spf2.set_v2_pra();
    spf2.append_mechanism(Mechanism::a(Qualifier::Pass));
    spf2.append_mechanism(Mechanism::all(Qualifier::Neutral));

    println!("\nNew spf 2: >{}<", spf2);
    let spf_as_json = serde_json::to_string_pretty(&spf2).unwrap();
    println!("JSON:\n{}", spf_as_json);
}
