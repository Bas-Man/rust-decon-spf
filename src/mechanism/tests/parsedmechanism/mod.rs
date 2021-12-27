#[cfg(test)]
mod test_a {
    use crate::mechanism::MechanismError;
    use crate::mechanism::ParsedMechanism;
    #[test]
    fn make_mechanism() {
        let m: ParsedMechanism = "ip4:203.32.160.0/24".parse().unwrap();
        assert_eq!(m.network().kind().is_ip(), true);
        assert_eq!(m.network().qualifier().is_pass(), true);
        assert_eq!(m.network().raw(), "203.32.160.0/24");
        assert_eq!(m.network().to_string(), "ip4:203.32.160.0/24");
        assert_eq!(m.is_network(), true);
        assert_eq!(m.network().as_network().prefix(), 24);
        assert_eq!(m.network().to_string(), "ip4:203.32.160.0/24");
    }
    #[test]
    fn make_mechanism_a() {
        let m: ParsedMechanism = "a".parse().unwrap();
        assert_eq!(m.txt().kind().is_a(), true);
        assert_eq!(m.txt().qualifier().is_pass(), true);
        assert_eq!(m.txt().raw(), "a");
        assert_eq!(m.txt().to_string(), "a");
    }
    #[test]
    fn make_mechanism_a_colon() {
        let m: ParsedMechanism = "?a:test.com".parse().unwrap();
        assert_eq!(m.txt().kind().is_a(), true);
        assert_eq!(m.txt().qualifier().is_neutral(), true);
        assert_eq!(m.txt().raw(), "test.com");
        assert_eq!(m.txt().to_string(), "?a:test.com");
    }
    #[test]
    fn make_mechanism_a_colon_slash() {
        let m: ParsedMechanism = "?a:test.com/24".parse().unwrap();
        assert_eq!(m.txt().kind().is_a(), true);
        assert_eq!(m.txt().qualifier().is_neutral(), true);
        assert_eq!(m.txt().raw(), "test.com/24");
        assert_eq!(m.txt().to_string(), "?a:test.com/24");
    }
    #[test]
    fn make_mechanism_a_slash() {
        let m: ParsedMechanism = "?a/24".parse().unwrap();
        assert_eq!(m.txt().kind().is_a(), true);
        assert_eq!(m.txt().qualifier().is_neutral(), true);
        assert_eq!(m.txt().raw(), "/24");
        assert_eq!(m.txt().to_string(), "?a/24");
    }
    #[test]
    fn make_fail_a() {
        let m: Result<ParsedMechanism, MechanismError> = "ab".parse();
        assert_eq!(m.is_err(), true);
        let err = m.unwrap_err();
        assert_eq!(
            err,
            MechanismError::NotValidMechanismFormat("ab".to_string())
        );
        assert_eq!(
            err.to_string(),
            "ab does not conform to any Mechanism format."
        );
    }
}

#[cfg(test)]
mod redirect {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn parse_redirect() {
        let input = "redirect=_spf.example.com";
        let m = ParsedMechanism::new(input).unwrap();
        assert_eq!(m.txt().kind().is_redirect(), true);
        assert_eq!(m.txt().to_string(), "redirect=_spf.example.com");
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod a_invalid {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn check_a() {
        let input = "-a:example.xx";
        let m = ParsedMechanism::new(input);
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod mx_invalid {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn check_a() {
        let input = "+mx:example.xx";
        let m = ParsedMechanism::new(input);
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod include_invalid {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn check_a() {
        let input = "+include:example.xx";
        let m = ParsedMechanism::new(input);
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod ptr_invalid {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn check_a() {
        let input = "ptr:example.xx";
        let m = ParsedMechanism::new(input);
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
#[cfg(feature = "strict-dns")]
#[cfg(test)]
mod exists_invalid {
    use crate::mechanism::ParsedMechanism;

    #[test]
    fn check_a() {
        let input = "exists:example.xx";
        let m = ParsedMechanism::new(input);
        let err = m.unwrap_err();
        assert_eq!(
            err.to_string(),
            "example.xx is not a valid string for a host record."
        );
    }
}
