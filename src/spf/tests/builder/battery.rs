use crate::spf::SpfBuilder;
mod spf_v1 {
    use super::*;
    mod valid {
        use super::*;

        #[test]
        fn versions() {
            let list = vec!["v=spf1 a -all"];

            for item in list.into_iter() {
                let valid_spf: SpfBuilder = item.parse().unwrap();
                assert_eq!(valid_spf.is_valid(), false);
            }
        }
    }

    mod invalid {
        use super::*;
        use crate::SpfError;

        #[test]
        fn versions() {
            let list = vec!["v=spf a -all"];

            for item in list.into_iter() {
                let invalid_spf: SpfError = item.parse::<SpfBuilder>().unwrap_err();
                assert_eq!(invalid_spf, SpfError::InvalidSource)
            }
        }
    }
}

#[cfg(feature = "spf2")]
mod spf_v2 {
    mod valid {
        use super::*;

        #[test]
        fn versions() {
            let list = vec![
                "spf2.0/pra a -all",
                "spf2.0/mfrom a -all",
                "spf2.0/pra,mfrom a -all",
                "spf2.0/mfrom,pra a -all",
            ];

            for item in list.into_iter() {
                let valid_spf: SpfBuilder = item.parse().unwrap();
                assert_eq!(valid_spf.is_v2(), true);
            }
        }
    }

    mod invalid {
        use super::*;
        use crate::SpfError;

        #[test]
        fn versions() {
            let list = vec!["spf2.0/ a -all", "spf2.0 a -all"];

            for item in list.into_iter() {
                let invalid_spf: SpfError = item.parse::<SpfBuilder>().unwrap_err();
                assert_eq!(invalid_spf, SpfError::InvalidSource)
            }
        }
    }
    use super::*;
}
