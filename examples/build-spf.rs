use decon_spf::mechanism::{Kind, Mechanism, ParsedMechanism, Qualifier};
use decon_spf::SpfBuilder;

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

    let mut spf2 = SpfBuilder::new();
    spf2.set_v1();
    let ip = "203.32.166.0/24".parse().unwrap();
    let m = Mechanism::ip(Qualifier::Pass, ip);
    spf2.append_mechanism(m);

    println!("\nNew spf 2: >{}<", spf2);
    println!("Add mx to spf2");
    spf2.append_mechanism(Mechanism::mx(Qualifier::Pass));
    println!("Altered spf 2: >{}<", spf2);
    println!("Clear mx from spf2");
    spf2.clear_mechanism(Kind::MX);
    println!("Altered spf 2: >{}<", spf2);

    let mut spf3 = SpfBuilder::new();
    spf3.set_v2_pra();
    spf3.append_mechanism(Mechanism::a(Qualifier::Pass));
    spf3.append_mechanism(Mechanism::all_with_qualifier(Qualifier::Neutral));

    println!("\nNew spf 3: >{}<", spf3);
    println!("Change spf3 all to Fail");
    spf3.append_mechanism(Mechanism::all_default());
    println!("Altered spf 3: >{}<", spf3);
}
