#[cfg(test)]
use crate::spf::Spf;
use serde_json;

#[test]
fn spf_a() {
    let input = "v=spf1 a ~all";
    let spf: Spf = input.parse().unwrap();

    let spf_as_json = serde_json::to_string(&spf).unwrap();
    assert_eq!(spf_as_json,
               "{\"source\":\"v=spf1 a ~all\",\"version\":\"v=spf1\",\"from_src\":false,\"redirect\":null,\"is_redirected\":false,\"a\":[{\"kind\":\"A\",\"qualifier\":\"Pass\",\"rrdata\":null}],\"mx\":null,\"include\":null,\"ip4\":null,\"ip6\":null,\"ptr\":null,\"exists\":null,\"all\":{\"kind\":\"All\",\"qualifier\":\"SoftFail\",\"rrdata\":null},\"was_parsed\":true,\"was_validated\":false,\"is_valid\":false}");
    let spf_from_json: Spf = serde_json::from_str(&spf_as_json).unwrap();
    assert_eq!(spf_from_json, spf);
}

#[test]
fn test_a_mechanism_colon_slash() {
    let input = "v=spf1 ~a:example.com/24 ~all";

    let spf: Spf = input.parse().unwrap();
    let spf_as_json = serde_json::to_string(&spf).unwrap();
    assert_eq!(spf_as_json,
               "{\"source\":\"v=spf1 ~a:example.com/24 ~all\",\"version\":\"v=spf1\",\"from_src\":false,\"redirect\":null,\"is_redirected\":false,\"a\":[{\"kind\":\"A\",\"qualifier\":\"SoftFail\",\"rrdata\":\"example.com/24\"}],\"mx\":null,\"include\":null,\"ip4\":null,\"ip6\":null,\"ptr\":null,\"exists\":null,\"all\":{\"kind\":\"All\",\"qualifier\":\"SoftFail\",\"rrdata\":null},\"was_parsed\":true,\"was_validated\":false,\"is_valid\":false}");
    let spf_from_json: Spf = serde_json::from_str(&spf_as_json).unwrap();
    assert_eq!(spf_from_json, spf);
}
