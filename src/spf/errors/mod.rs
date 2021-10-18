use ipnetwork::IpNetworkError;

/// A list of expected possible errors for SPF records.
#[derive(Debug, PartialEq)]
pub enum SpfErrorType {
    /// Source is invalid, SPF struct was not created using `from_str()`
    InvalidSource,
    /// Source string length exceeds 255 Characters
    SourceLengthExceeded,
    /// Exceeds RFC lookup limit.
    LookupLimitExceeded,
    /// Source Spf String has not been parsed.
    HasNotBeenParsed,
    /// Only one white space is permitted bdtween mechanisms.
    WhiteSpaceSyntaxError,
    /// Invalid SPF
    InvalidSPF,
    /// Rediect with additional Mechanisms
    RedirectWithAllMechanism,
    /// Network Address is not valid Error.
    InvalidIPAddr(IpNetworkError),
}
impl std::fmt::Display for SpfErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfErrorType::InvalidSource => write!(f, "Source string not valid."),
            SpfErrorType::SourceLengthExceeded => write!(f, "Spf record exceeds 255 characters."),
            SpfErrorType::LookupLimitExceeded => write!(f, "Too many DNS lookups."),
            SpfErrorType::HasNotBeenParsed => write!(f, "Source string has not been parsed."),
            SpfErrorType::WhiteSpaceSyntaxError => {
                write!(
                    f,
                    "Spf contains two or more consecutive whitespace characters."
                )
            }
            SpfErrorType::InvalidSPF => write!(f, "Spf record is invalid."),
            SpfErrorType::RedirectWithAllMechanism => {
                write!(f, "Redirect with unexpected 'All' Mechanism")
            }
            SpfErrorType::InvalidIPAddr(err) => write!(f, "{}", err.to_string()),
        }
    }
}

impl From<IpNetworkError> for SpfErrorType {
    fn from(err: IpNetworkError) -> Self {
        SpfErrorType::InvalidIPAddr(err)
    }
}

impl std::error::Error for SpfErrorType {}

impl SpfErrorType {
    /// Returns `true` if the SpfError is any of those listed [`SpfErrorType`](SpfErrorType).
    pub fn is_spf_error(&self) -> bool {
        matches!(self, Self::InvalidSource)
            || matches!(self, Self::SourceLengthExceeded)
            || matches!(self, Self::LookupLimitExceeded)
            || matches!(self, Self::HasNotBeenParsed)
            || matches!(self, Self::InvalidSPF)
            || matches!(self, Self::RedirectWithAllMechanism)
            || matches!(self, Self::InvalidIPAddr(_))
    }
    /// Returns `true` if the SpfError indicates and Invalid Source error.
    pub fn is_invalid_source(&self) -> bool {
        matches!(self, Self::InvalidSource)
    }
    /// Returns `true` if the SpfError indictes source length exceeds 255 characters.
    pub fn is_source_length_exceeded(&self) -> bool {
        matches!(self, Self::SourceLengthExceeded)
    }
    /// Returns `true` if the SpfError indicates SPF contains more than 10 DNS lookups.
    pub fn is_lookup_limit_exceeded(&self) -> bool {
        matches!(self, Self::LookupLimitExceeded)
    }
    /// Returns `true` if the SpfError indicates source of Spf has not been parsed.
    pub fn is_has_not_been_parsed(&self) -> bool {
        matches!(self, Self::HasNotBeenParsed)
    }
    /// Returns `true` if the SpfError indicates this is an invalid Spf Record.
    pub fn is_invalid_spf(&self) -> bool {
        matches!(self, Self::InvalidSPF)
    }
    /// Returns `true` if the SpfError indicates the presents of `All` Mechanism with
    pub fn is_redirect_with_all_mechanism(&self) -> bool {
        matches!(self, Self::RedirectWithAllMechanism)
    }
    /// Returns `true` if the SpfError indicates an Invalid IP Address
    pub fn is_invalid_ip_addr(&self) -> bool {
        matches!(self, Self::InvalidIPAddr(_))
    }
}

#[test]
fn is_any_spf_error() {
    let err = SpfErrorType::InvalidSource;
    assert_eq!(err.is_spf_error(), true);
}
#[test]
fn is_invalid_source() {
    let err = SpfErrorType::InvalidSource;
    assert_eq!(err.is_invalid_source(), true);
}
#[test]
fn is_source_length_exceeded() {
    let err = SpfErrorType::SourceLengthExceeded;
    assert_eq!(err.is_source_length_exceeded(), true);
}
#[test]
fn is_lookup_limit_exceeded() {
    let err = SpfErrorType::LookupLimitExceeded;
    assert_eq!(err.is_lookup_limit_exceeded(), true)
}
#[test]
fn is_has_not_been_parsed() {
    let err = SpfErrorType::HasNotBeenParsed;
    assert_eq!(err.is_has_not_been_parsed(), true)
}
#[test]
fn is_invalid_spf() {
    let err = SpfErrorType::InvalidSPF;
    assert_eq!(err.is_invalid_spf(), true)
}
#[test]
fn is_redirect_with_all_mechanism() {
    let err = SpfErrorType::RedirectWithAllMechanism;
    assert_eq!(err.is_redirect_with_all_mechanism(), true)
}
#[test]
fn is_invalid_ip_addr() {
    let bad_ip = "203.32.160.0/33"
        .parse::<ipnetwork::IpNetwork>()
        .unwrap_err();
    let err = SpfErrorType::InvalidIPAddr(bad_ip);
    assert_eq!(err.is_invalid_ip_addr(), true)
}
