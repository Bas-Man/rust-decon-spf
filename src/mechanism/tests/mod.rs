mod mechimpl;

#[cfg(test)]
mod test_a {
    use crate::mechanism::Mechanism;
    use crate::mechanism::Qualifier;
    #[test]
    fn make_a() {
        let m = Mechanism::new_a(Qualifier::Pass, None);
        assert_eq!(m.kind().is_a(), true);
        assert_eq!(m.qualifier().is_pass(), true);
        assert_eq!(m.raw(), "a");
    }
}
