use crate::spf::Spf;
mod a {
    use super::*;
    #[test]
    fn default() {
        let input = "v=spf1 a -all";
        let spf: Spf<String> = input.parse().unwrap();
        assert_eq!(spf.source, input);
        assert_eq!(spf.mechanisms.len(), 2);
    }
}
