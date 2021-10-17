use decon_spf::mechanism::{Kind, Mechanism, Qualifier};
use decon_spf::spf::Spf;

fn main() {
    let mut spf1 = Spf::new();
    spf1.set_v1();
    spf1.append_ip_mechanism(Mechanism::new_ip(
        Qualifier::Pass,
        "203.32.160.0/32".parse().unwrap(),
    ));

    println!("New spf 1: >{}<", spf1);

    let mut spf2 = Spf::new();
    spf2.set_v1();
    let ip = "203.32.166.0/24".parse().unwrap();
    spf2.append_ip_mechanism(Mechanism::new_ip(Qualifier::Pass, ip));

    println!("\nNew spf 2: >{}<", spf2);
    println!("Add mx to spf2");
    spf2.append_mechanism(Mechanism::new_mx_without_mechanism(Qualifier::Pass));
    println!("Altered spf 2: >{}<", spf2);
    println!("Clear mx from spf2");
    spf2.clear_mechanism(Kind::MX);
    println!("Altered spf 2: >{}<", spf2);

    let mut spf3 = Spf::new();
    spf3.set_v2_pra();
    spf3.append_mechanism(Mechanism::new_a_without_mechanism(Qualifier::Pass));
    spf3.append_mechanism(Mechanism::new_all(Qualifier::Neutral));

    println!("\nNew spf 3: >{}<", spf3);
    println!("Change spf3 all to Fail");
    spf3.append_mechanism(Mechanism::new_all(Qualifier::Fail));
    println!("Altered spf 3: >{}<", spf3);
}
