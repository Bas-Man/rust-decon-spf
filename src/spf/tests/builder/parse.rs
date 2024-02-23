mod valid_spf_from_str {
    use crate::spf::SpfBuilder;
    use crate::spf::SpfError;

    #[test]
    fn test_redirect() {
        let input = "v=spf1 redirect=_spf.google.com";

        let spf: SpfBuilder = input.parse().unwrap();

        assert_eq!(spf.is_redirect(), true);
        assert_eq!(spf.include.is_none(), true);
        assert_eq!(spf.a.is_none(), true);
        assert_eq!(spf.mx.is_none(), true);
        assert_eq!(spf.ip4.is_none(), true);
        assert_eq!(spf.ip6.is_none(), true);
        assert_eq!(spf.ptr.is_none(), true);
        assert_eq!(spf.exists.is_none(), true);
        assert_eq!(spf.all.is_none(), true);
        assert_eq!(spf.redirect().unwrap().qualifier().as_str(), "");
        assert_eq!(spf.redirect().unwrap().raw(), "_spf.google.com");
        assert_eq!(
            spf.redirect().unwrap().to_string(),
            "redirect=_spf.google.com"
        );
        assert_eq!(
            spf.to_string(),
            "v=spf1 redirect=_spf.google.com".to_string()
        );
    }

    #[test]
    fn test_hotmail() {
        let input = "v=spf1 ip4:157.55.9.128/25 include:spf.protection.outlook.com include:spf-a.outlook.com include:spf-b.outlook.com include:spf-a.hotmail.com include:_spf-ssg-b.microsoft.com include:_spf-ssg-c.microsoft.com ~all";

        let spf: SpfBuilder = input.parse().unwrap();

        assert_eq!(spf.is_redirect(), false);
        assert_eq!(!spf.includes().unwrap().is_empty(), true);
        assert_eq!(spf.includes().unwrap().len(), 6);
        assert_eq!(
            spf.includes().unwrap()[0].to_string(),
            "include:spf.protection.outlook.com"
        );
        assert_eq!(spf.ip4().unwrap().len(), 1);
        assert_eq!(spf.ip4().unwrap()[0].to_string(), "ip4:157.55.9.128/25");
        assert_eq!(spf.all().unwrap().to_string(), "~all");
    }

    #[test]
    fn test_netblocks2_google_com() {
        let input = "v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all";

        let spf: SpfBuilder = input.parse().unwrap();
        assert_eq!(spf.includes().is_none(), true);
        assert_eq!(spf.ip4().is_none(), true);
        assert_eq!(!spf.ip6().is_none(), true);
        assert_eq!(spf.ip6().unwrap().len(), 6);
        assert_eq!(spf.ip6().unwrap()[0].to_string(), "ip6:2001:4860:4000::/36");
        assert_eq!(
            spf.ip6().unwrap()[0].as_network().to_string(),
            "2001:4860:4000::/36"
        );
        assert_eq!(spf.all().unwrap().to_string(), "~all");
    }

    #[test]
    fn valid_spf1() {
        let input = "v=spf1 a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_ok(), true);
    }

    #[test]
    fn valid_spf2() {
        let input = "spf2.0/pra a";
        let spf: SpfBuilder = input.parse().unwrap();

        assert_eq!(spf.version(), "spf2.0/pra");
    }
}

#[cfg(test)]
mod invalid_spf_from_str {
    use crate::spf::SpfBuilder;
    use crate::spf::SpfError;

    #[test]
    fn invalid_spf1() {
        let input = "v=sf a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_err(), true);
        let err = spf.unwrap_err();
        assert_eq!(err.is_spf_error(), true);
        assert_eq!(err.is_invalid_source(), true);
        assert_eq!(err.to_string(), "Source string not valid.");
        assert_eq!(err, SpfError::InvalidSource);
    }

    #[test]
    fn invalid_spf2() {
        let input = "spf2 a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_err(), true);
    }

    #[test]
    fn valid_spf2_pra() {
        let input = "spf2.0/pra a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_ok(), true);
    }

    #[test]
    fn valid_spf2_mfrom() {
        let input = "spf2.0/mfrom a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_ok(), true);
    }

    #[test]
    fn valid_spf2_mfrom_pra() {
        let input = "spf2.0/mfrom,pra a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_ok(), true);
    }

    #[test]
    fn valid_spf2_pra_mfrom() {
        let input = "spf2.0/pra,mfrom a";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_ok(), true);
    }
}

#[cfg(test)]
mod invalid_ip {
    use crate::mechanism::MechanismError::InvalidIPNetwork;
    use crate::spf::SpfBuilder;
    use crate::spf::SpfError;
    use crate::SpfError::InvalidMechanism;
    use ipnetwork::IpNetworkError::InvalidAddr;

    #[test]
    fn invalid_ip4() {
        let input = "v=spf1 ip4:203.32.10.0/33";
        let spf: Result<SpfBuilder, SpfError> = input.parse();
        assert_eq!(spf.is_err(), true);
        let error = spf.unwrap_err();
        assert_eq!(
            error,
            InvalidMechanism(InvalidIPNetwork(InvalidAddr("203.32.10.0/33".to_string())))
        );
        assert_eq!(error.is_invalid_ip_addr(), true);
        assert_eq!(error.to_string(), "invalid address: 203.32.10.0/33");
    }

    #[test]
    fn invalid_ip6() {
        let input = "v=spf1 ip6:2001:4860:4000::/129";
        let spf: Result<SpfBuilder, SpfError> = input.parse();

        assert_eq!(spf.is_err(), true);
        let error = spf.unwrap_err();
        assert_eq!(error.is_invalid_ip_addr(), true);
        assert_eq!(error.to_string(), "invalid address: 2001:4860:4000::/129");
    }
}
