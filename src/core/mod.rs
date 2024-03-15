use crate::mechanism::{Mechanism, Qualifier};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use regex::Regex;
pub(crate) mod spf_regex;

/// This is the maximum number of characters that an Spf Record can store.
pub(crate) const MAX_SPF_STRING_LENGTH: usize = 255;

/// Spf Versions
pub(crate) const VSPF1: &str = "v=spf1";
pub(crate) const SPF2_PRA: &str = "spf2.0/pra";
pub(crate) const SPF2_MFROM: &str = "spf2.0/mfrom";
pub(crate) const SPF2_PRA_MFROM: &str = "spf2.0/pra,mfrom";
pub(crate) const SPF2_MFROM_PRA: &str = "spf2.0/mfrom,pra";

/// Mechanism Const Slices
pub(crate) const REDIRECT: &str = "redirect=";
pub(crate) const INCLUDE: &str = "include:";
pub(crate) const ALL: &str = "all";
pub(crate) const IP4: &str = "ip4:";
pub(crate) const IP6: &str = "ip6:";

/// Check for white space in spf record.
///
/// Return true if there is a space at the end of the string or
/// if there are two consecutive spaces within the string.
pub(crate) fn spf_check_whitespace(s: &str) -> bool {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"\s{2,}").unwrap();
        static ref ENDING_SPACE: Regex = Regex::new(r"\s$").unwrap();
    }
    RE.is_match(s) || ENDING_SPACE.is_match(s)
}

pub(crate) fn char_to_qualifier(c: char) -> Qualifier {
    match c {
        '+' => Qualifier::Pass,
        '-' => Qualifier::Fail,
        '~' => Qualifier::SoftFail,
        '?' => Qualifier::Neutral,
        _ => Qualifier::Pass,
    }
}

#[doc(hidden)]
// Check if the initial character in the string `record` matches `c`
// If they do no match then return the initial character
// if c matches first character of record, we can `+`, a blank modifier equates to `+`
pub(crate) fn return_and_remove_qualifier(record: &str, c: char) -> (Qualifier, &str) {
    // Returns a tuple of (qualifier, &str)
    // &str will have had the qualifier character removed if it existed. The &str will be unchanged
    // if the qualifier was not present
    if c != record.chars().next().unwrap() {
        // qualifier exists. return tuple of qualifier and `record` with qualifier removed.
        (
            char_to_qualifier(record.chars().next().unwrap()),
            remove_qualifier(record),
        )
    } else {
        // qualifier does not exist, default to `+` and return unmodified `record`
        (Qualifier::Pass, record)
    }
}

#[cfg(test)]
mod return_and_remove_qualifier_tests {
    use super::*;
    #[test]
    fn return_and_remove_qualifier_no_qualifier() {
        let source = "no prefix";
        let (c, new_str) = return_and_remove_qualifier(source, 'n');
        assert_eq!(Qualifier::Pass, c);
        assert_eq!(source, new_str);
    }

    #[test]
    fn return_and_remove_qualifier_pass() {
        let source = "+prefix";
        let (c, new_str) = return_and_remove_qualifier(source, 'n');
        assert_eq!(Qualifier::Pass, c);
        assert_eq!("prefix", new_str);
    }

    #[test]
    fn return_and_remove_qualifier_fail() {
        let source = "-prefix";
        let (c, new_str) = return_and_remove_qualifier(source, 'n');
        assert_eq!(Qualifier::Fail, c);
        assert_eq!("prefix", new_str);
    }

    #[test]
    fn return_and_remove_qualifier_softfail() {
        let source = "~prefix";
        let (c, new_str) = return_and_remove_qualifier(source, 'n');
        assert_eq!(Qualifier::SoftFail, c);
        assert_eq!("prefix", new_str);
    }

    #[test]
    fn return_and_remove_qualifier_neutral() {
        let source = "?prefix";
        let (c, new_str) = return_and_remove_qualifier(source, 'n');
        assert_eq!(Qualifier::Neutral, c);
        assert_eq!("prefix", new_str);
    }
}
#[doc(hidden)]
pub(crate) fn remove_qualifier(record: &str) -> &str {
    // Remove leading (+,-,~,?) character and return an updated str
    let mut chars = record.chars();
    chars.next();
    chars.as_str()
}
#[test]
fn test_remove_qualifier() {
    let test_str = "abc";
    let result = remove_qualifier(test_str);
    assert_eq!(result, "bc");
}

// builds a string representation of the mechanisms stored in the Vec<Mechanism<String>>
pub(crate) fn build_spf_str(str: &[Mechanism<String>]) -> String {
    let mut partial_spf = String::new();
    for i in str.iter() {
        partial_spf.push_str(&format!(" {}", i.to_string().as_str()));
    }
    partial_spf
}

// builds a string representation of the mechanisms stored in the Vec<Mechanism<IpNetwork>>
pub(crate) fn build_spf_str_from_ip(str: &[Mechanism<IpNetwork>]) -> String {
    let mut partial_spf = String::new();
    for i in str.iter() {
        partial_spf.push_str(&format!(" {}", i.to_string().as_str()));
    }
    partial_spf
}

#[cfg(feature = "strict-dns")]
pub(crate) mod dns {
    use addr::parse_dns_name;

    /// If there is a string preceding the '/' character. This string should be returned.
    ///
    /// Example:
    /// bogus.com/24
    ///
    /// Returns "bogus.com"
    /// If there is no '/' or the string starts with a '/' than an unmodified `str`
    /// is returned.
    pub(crate) fn get_domain_before_slash(s: &str) -> &str {
        if !s.starts_with('/') && s.contains('/') {
            s.split('/').next().unwrap()
        } else {
            s
        }
    }

    /// Checks that the domain name string has a valid suffix, meaning that it is
    /// listed in the public suffix list.
    ///
    /// Returns: a boolean value
    pub(crate) fn is_dns_suffix_valid(name: &str) -> bool {
        // These can not be and do not need to be tested. They are always valid.
        if name == "a" || name == "mx" || name == "ptr" || name == "all" || name.starts_with('/') {
            true
        } else {
            match parse_dns_name(name) {
                Err(_) => false,
                Ok(dns) => dns.has_known_suffix(),
            }
        }
    }
    #[cfg(feature = "strict-dns")]
    pub(crate) mod warn {
        use crate::core::dns::is_dns_suffix_valid;

        #[allow(dead_code)]
        pub(crate) fn check_for_dns_warning(warning_vec: &mut Vec<String>, name: &str) {
            if !is_dns_suffix_valid(name) {
                warning_vec.push(name.to_string());
            }
        }
        #[cfg(test)]
        mod test {
            use crate::core::dns::{get_domain_before_slash, is_dns_suffix_valid};

            #[test]
            fn start_with_slash() {
                let input = "/24";
                assert_eq!(get_domain_before_slash(input), "/24");
            }
            #[test]
            fn domain_contains_slash() {
                let input = "test.com/24";
                assert_eq!(get_domain_before_slash(input), "test.com");
            }
            #[test]
            fn domain_without_slash() {
                let input = "test.com";
                assert_eq!(get_domain_before_slash(input), "test.com");
            }
            #[test]
            fn invalid_tld() {
                assert_eq!(is_dns_suffix_valid("t.xx"), false);
            }
            #[test]
            fn valid_domain() {
                assert_eq!(is_dns_suffix_valid("test.com"), true);
            }
            #[test]
            fn valid_a() {
                assert_eq!(is_dns_suffix_valid("a"), true);
            }
            #[test]
            fn valid_mx() {
                assert_eq!(is_dns_suffix_valid("mx"), true);
            }
            #[test]
            fn valid_ptr() {
                assert_eq!(is_dns_suffix_valid("ptr"), true);
            }
        }
    }
    pub(crate) mod strict {
        mod test {}
    }
}
