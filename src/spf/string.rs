use crate::mechanism::{Kind, Mechanism};
use crate::spf::validate::{self, Validate};
use crate::{Spf, SpfError};
use ipnetwork::IpNetwork;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

impl Display for Spf<String> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !&self.source.is_empty() {
            write!(f, "{}", self.source)
        } else {
            let mut spf_string = String::new();
            spf_string.push_str(self.version().as_str());
            for m in self.iter() {
                spf_string.push_str(format!(" {}", m).as_str());
            }
            write!(f, "{}", spf_string)
        }
    }
}

impl FromStr for Spf<String> {
    type Err = SpfError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        validate::check_start_of_spf(s)?;
        validate::check_spf_length(s)?;
        validate::check_whitespaces(s)?;

        // Index of Redirect Mechanism
        let mut redirect_idx: usize = 0;
        // There exists a redirect mechanism
        let mut redirect = false;
        // Index of All Mechanism
        let mut all_idx = 0;
        let mut idx = 0;
        let mut spf = Spf::default();
        let mechanisms = s.split_whitespace();
        for m in mechanisms {
            if m.contains(crate::core::SPF1) {
                spf.version = m.to_string();
            } else if m.contains(crate::core::IP4) || m.contains(crate::core::IP6) {
                let m_ip = m.parse::<Mechanism<IpNetwork>>()?;
                spf.mechanisms.push(m_ip.into());
            } else {
                let m_str = m.parse::<Mechanism<String>>()?;
                match *m_str.kind() {
                    Kind::Redirect => {
                        if !redirect {
                            redirect = true;
                            redirect_idx = idx;
                        } else {
                            return Err(SpfError::ModifierMayOccurOnlyOnce(Kind::Redirect));
                        }
                    }
                    Kind::All => all_idx = idx,
                    _ => {}
                }
                spf.mechanisms.push(m_str);
                idx += 1;
            }
        }
        if redirect {
            // all_idx should not be greater han redirect_idx.
            // all_idx should be 0 if a redirect mechanism was parsed.
            if all_idx > redirect_idx {
                return Err(SpfError::RedirectWithAllMechanism);
            }
            // redirect_idx should be the last item if it exists.
            if redirect_idx != idx - 1 {
                return Err(SpfError::RedirectNotFinalMechanism(redirect_idx as u8));
            }
        }
        spf.source = s.to_string();
        spf.redirect_idx = redirect_idx;
        spf.all_idx = all_idx;
        Ok(spf)
    }
}

impl TryFrom<&str> for Spf<String> {
    type Error = SpfError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Spf::from_str(s)
    }
}

impl Spf<String> {
    /// Creates a `Spf<String>` from the passed str reference.
    /// This is basically a rapper around FromStr which has been implemented for `Spf<String>`
    #[allow(dead_code)]
    pub fn new(s: &str) -> Result<Self, SpfError> {
        s.parse::<Spf<String>>()
    }

    /// Check that version is v1
    pub fn is_v1(&self) -> bool {
        self.version.contains(crate::core::SPF1)
    }
    /// Give access to the redirect modifier if present
    pub fn redirect(&self) -> Option<&Mechanism<String>> {
        if self.redirect_idx == 0 {
            return match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::Redirect => return self.mechanisms.first(),
                _ => None,
            };
        } else {
            Some(&self.mechanisms[self.redirect_idx])
        }
    }
    /// Give access to the `all` mechanism if it is present.
    pub fn all(&self) -> Option<&Mechanism<String>> {
        if self.all_idx == 0 {
            return match self
                .mechanisms
                .first()
                .expect("There should be a Mechanism<>")
                .kind()
            {
                Kind::All => return self.mechanisms.first(),
                _ => None,
            };
        } else {
            Some(&self.mechanisms[self.all_idx])
        }
    }
    #[allow(dead_code)]
    fn validate(&self) -> Result<(), SpfError> {
        self.validate_version()?;
        self.validate_length()?;
        #[cfg(feature = "ptr")]
        self.validate_ptr()?;
        self.validate_lookup_count()?;
        self.validate_redirect_all()?;
        Ok(())
    }
}
