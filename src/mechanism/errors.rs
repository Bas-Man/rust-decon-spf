/// Error message when unable to construct a new Mechanism.
#[derive(Debug, Clone, PartialEq)]
pub enum MechanismError {
    /// Indicates that the provided string is not correctly formed.
    InvalidMechanismFormat(String),
    ///. Indicates that the provided string does not match the required format for the Mechanism Kind.
    InvalidMechanismFormatByKind(String, String),
    /// Indicates that the provided string could not be parsed into an IpNetwork::IP4 though it is a valid IpNetwork.
    NotIP4Network(String),
    /// Indicates that the provided string could not be parsed into an IpNetwork::IP6 though it is a valid IpNetwork.
    NotIP6Network(String),
    /// Indicates that the provided string does not contain any valid IpNetwork.
    InvalidIPNetwork(ipnetwork::IpNetworkError),
    /// Attempted to access a Mechanism as a `Mechanism<IpNetwork>` but is `Mechanism<String>`
    NotIpNetworkMechanism,
    /// Attempted to access a Mechanism as a `Mechanism<String>` but is `Mechanism<IpNetwork>`
    NotStringMechanism,
    /// Indicates that the host record is not valid. Does not conform to RFC1123
    InvalidDomainHost(String),
}

impl std::fmt::Display for MechanismError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MechanismError::InvalidMechanismFormat(mesg) => {
                write!(f, "{} does not conform to any Mechanism format", mesg)
            }
            MechanismError::InvalidMechanismFormatByKind(kind, text) => {
                write!(
                    f,
                    "{} does not conform to Mechanism `{}` format",
                    text, kind
                )
            }
            MechanismError::NotIP4Network(mesg) => {
                write!(f, "{} is not an ip4 network", mesg)
            }
            MechanismError::NotIP6Network(mesg) => {
                write!(f, "{} is not an ip6 network", mesg)
            }
            MechanismError::InvalidIPNetwork(ip_error) => {
                write!(f, "{}", ip_error)
            }
            MechanismError::NotIpNetworkMechanism => {
                write!(f, "Attempt to access TXT as IP")
            }
            MechanismError::NotStringMechanism => {
                write!(f, "Attempt to access IP as TXT")
            }
            MechanismError::InvalidDomainHost(host) => {
                write!(f, "Invalid DNS string: {}", host)
            }
        }
    }
}
impl MechanismError {
    /// Returns `true` if it is not a valid Mechanism format.
    pub fn is_invalid_format(&self) -> bool {
        matches!(self, Self::InvalidMechanismFormat(_))
            || matches!(self, Self::InvalidMechanismFormatByKind(_, _))
    }
    /// Return `true` if it is a valid IpNetwork but not an IP4 network.
    /// # Example:
    /// "ip4:2001:4860:4000::/36" would give this error.
    /// Expected an IP4 network but given an IP6 network.
    pub fn is_not_ip4_network(&self) -> bool {
        matches!(self, Self::NotIP4Network(_))
    }
    /// Return `true` if it is a valid IpNetwork but not an IP6 network.
    /// # Example:
    /// "ip4:203.32.160.0/24" would give this error.
    /// Expected an IP6 network but given an IP4 network.
    pub fn is_not_ip6_network(&self) -> bool {
        matches!(self, Self::NotIP6Network(_))
    }
    /// Return `true` if it the string can not be parsed to an IpNetwork
    /// # Example:
    /// "ip4:203.32.160.0/33" would give this error. This applies to IP6 networks.
    pub fn is_invalid_ip(&self) -> bool {
        matches!(self, Self::InvalidIPNetwork(_))
    }
}

impl std::error::Error for MechanismError {}
