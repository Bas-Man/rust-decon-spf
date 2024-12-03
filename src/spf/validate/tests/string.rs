mod valid {
    use crate::mechanism::Mechanism;
    use crate::Spf;
    use std::convert::TryFrom;

    #[test]
    fn basic() {
        let spf = Spf::try_from("v=spf1 -all");
        assert!(spf.is_ok());
        let result = spf.unwrap();
        assert_eq!(result.to_string(), "v=spf1 -all");
        assert_eq!(result.all_idx, 0);
        assert_eq!(result.redirect_idx, 0);
        assert_eq!(result.redirect(), None);
        let m: Mechanism<String> = "-all".parse::<Mechanism<String>>().unwrap();
        assert_eq!(result.all(), Some(&m));
    }
}

mod invalid {
    use crate::{Spf, SpfError};
    use std::convert::TryFrom;

    #[test]
    fn invalid() {
        let spf = Spf::try_from("v=spf3 -all");
        assert!(spf.is_err());
        assert_eq!(spf.unwrap_err(), SpfError::InvalidVersion);
    }
}
