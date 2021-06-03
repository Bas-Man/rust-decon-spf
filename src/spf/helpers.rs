use crate::spf::kinds;
use crate::spf::mechanism::Mechanism;
use crate::spf::qualifier::Qualifier;
use regex::Regex;

#[doc(hidden)]
pub(crate) fn capture_matches(
    pattern: Regex,
    string: &str,
    kind: kinds::MechanismKind,
) -> Option<Mechanism<String>> {
    let caps = pattern.captures(string);
    let q: char;
    let mut q2: Qualifier = Qualifier::Pass;
    let m: String;
    let mechanism;
    match caps {
        None => return None,
        Some(caps) => {
            // There was a match
            if caps.name("qualifier").is_some() {
                q = caps
                    .name("qualifier")
                    .unwrap()
                    .as_str()
                    .chars()
                    .nth(0)
                    .unwrap();
                q2 = char_to_qualifier(q);
            };
            if caps.name("mechanism").is_some() {
                m = caps.name("mechanism").unwrap().as_str().to_string();
                mechanism = Mechanism::new(kind, q2, (*m).to_string());
            } else {
                m = match kind {
                    kinds::MechanismKind::A => "a".to_string(),
                    kinds::MechanismKind::MX => "mx".to_string(),
                    kinds::MechanismKind::Ptr => "ptr".to_string(),
                    _ => unreachable!(),
                };
                mechanism = Mechanism::new(kind, q2, m);
            }

            Some(mechanism)
        }
    }
}

pub(crate) fn char_to_qualifier(c: char) -> Qualifier {
    match c {
        '+' => return Qualifier::Pass,
        '-' => return Qualifier::Fail,
        '~' => return Qualifier::SoftFail,
        '?' => return Qualifier::Neutral,
        _ => return Qualifier::Pass, // This should probably be Neutral
    }
}
