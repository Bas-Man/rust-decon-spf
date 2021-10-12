use decon_spf::spf::mechanism::Mechanism;
use decon_spf::spf::qualifier::Qualifier;
use decon_spf::spf::Spf;

fn main() {
    let mut spf = Spf::new();
    spf.set_v1();
    spf.append_ip_mechanism(Mechanism::new_ip(
        Qualifier::Pass,
        "203.32.160.0/32".parse().unwrap(),
    ));

    println!("New spf: {}", spf.to_string());
}
