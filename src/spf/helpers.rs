use crate::spf::kinds;
use crate::spf::mechanism::Mechanism;
use crate::spf::qualifier::Qualifier;
use regex::Regex;

pub(crate) fn capture_matches(
    pattern: Regex,
    string: &str,
    kind: kinds::MechanismKind,
) -> Option<Mechanism<String>> {
    let caps = pattern.captures(string);
    let qualifier_char: char;
    let mut qualifier_result: Qualifier = Qualifier::Pass;
    let mechanism_string: String;
    let mechanism;
    match caps {
        None => return None,
        Some(caps) => {
            // There was a match
            if caps.name("qualifier").is_some() {
                qualifier_char = caps
                    .name("qualifier")
                    .unwrap()
                    .as_str()
                    .chars()
                    .nth(0)
                    .unwrap();
                qualifier_result = char_to_qualifier(qualifier_char);
            };
            if caps.name("mechanism").is_some() {
                mechanism_string = caps.name("mechanism").unwrap().as_str().to_string();
                mechanism = Mechanism::new(kind, qualifier_result, (*mechanism_string).to_string());
            } else {
                mechanism_string = match kind {
                    kinds::MechanismKind::A => "a".to_string(),
                    kinds::MechanismKind::MX => "mx".to_string(),
                    kinds::MechanismKind::Ptr => "ptr".to_string(),
                    _ => unreachable!(),
                };
                mechanism = Mechanism::new(kind, qualifier_result, mechanism_string);
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
