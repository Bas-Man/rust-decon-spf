use crate::mechanism::{Mechanism, Qualifier};
use crate::SpfBuilder;
use ipnetwork::IpNetwork;

#[test]
fn basic() {
    let input = "v=spf1 a mx -all";

    let mut spf: SpfBuilder = SpfBuilder::new();
    spf.set_v1()
        .append_mechanism(Mechanism::a(Qualifier::Pass))
        .append_mechanism(Mechanism::mx(Qualifier::Pass));
    let spf = spf.add_all(Mechanism::all());
    assert_eq!(spf.to_string(), input);
}

#[test]
fn include_x2() {
    let input = "v=spf1 include:test.com include:example.com -all";

    let mut spf: SpfBuilder = SpfBuilder::new();
    spf.set_v1()
        .append_mechanism(Mechanism::include(Qualifier::Pass, "test.com").unwrap())
        .append_mechanism(Mechanism::include(Qualifier::Pass, "example.com").unwrap());
    let spf = spf.add_all(Mechanism::all().into());
    assert_eq!(spf.includes().unwrap().len(), 2);
    assert_eq!(spf.to_string(), input);
}

#[test]
fn ip4_x3() {
    let input = "v=spf1 ip4:203.32.160.0/24 ip4:203.32.166.0/24 ip4:203.32.161.0/24 -all";

    let mut spf: SpfBuilder = SpfBuilder::new();
    spf.set_v1();
    spf.add_ip(
        "ip4:203.32.160.0/24"
            .parse::<Mechanism<IpNetwork>>()
            .unwrap(),
    );
    spf.add_ip(
        "ip4:203.32.166.0/24"
            .parse::<Mechanism<IpNetwork>>()
            .unwrap(),
    );
    spf.add_ip(
        "ip4:203.32.161.0/24"
            .parse::<Mechanism<IpNetwork>>()
            .unwrap(),
    );
    let spf = spf.add_all(Mechanism::all().into());
    assert_eq!(spf.to_string(), input);
}
