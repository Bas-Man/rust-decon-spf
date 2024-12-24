use crate::Parsed;
#[cfg(test)]
use crate::SpfBuilder;
use serde_json;

#[test]
fn spf_a() {
    let input = "v=spf1 a ~all";
    let spf = input.parse::<SpfBuilder<Parsed>>().unwrap();

    let spf_as_json = serde_json::to_string(&spf).unwrap();
    assert_eq!(spf_as_json,
               "{\"version\":\"v=spf1\",\"redirect\":null,\"a\":[{\"kind\":\"A\",\"qualifier\":\"Pass\",\"rrdata\":null}],\"mx\":null,\"include\":null,\"ip4\":null,\"ip6\":null,\"ptr\":null,\"exists\":null,\"all\":{\"kind\":\"All\",\"qualifier\":\"SoftFail\",\"rrdata\":null}}");
    let spf_from_json: SpfBuilder<_> = serde_json::from_str(&spf_as_json).unwrap();
    assert_eq!(spf_from_json, spf);
}

#[test]
fn test_a_mechanism_colon_slash() {
    let input = "v=spf1 ~a:example.com/24 ~all";

    let spf = input.parse::<SpfBuilder<Parsed>>().unwrap();
    let spf_as_json = serde_json::to_string(&spf).unwrap();
    assert_eq!(spf_as_json,
               "{\"version\":\"v=spf1\",\"redirect\":null,\"a\":[{\"kind\":\"A\",\"qualifier\":\"SoftFail\",\"rrdata\":\"example.com/24\"}],\"mx\":null,\"include\":null,\"ip4\":null,\"ip6\":null,\"ptr\":null,\"exists\":null,\"all\":{\"kind\":\"All\",\"qualifier\":\"SoftFail\",\"rrdata\":null}}");
    let spf_from_json: SpfBuilder<_> = serde_json::from_str(&spf_as_json).unwrap();
    assert_eq!(spf_from_json, spf);
}
