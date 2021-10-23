/// Error message when unable to construct a new Mechanism.
#[derive(Debug, PartialEq)]
pub enum MechanismError {
    /// Indicates that the provided string is not correctly formed.
    NotValidMechanismFormat(String),
    /// Indcates that the provided string could not be parsed into an Ipnetwork::IP4 though it is valid IpNetwork.
    NotIP4Network(String),
    /// Indcates that the provided string could not be parsed into an Ipnetwork::IP6 though it is a valid IpNetwork.
    NotIP6Network(String),
    /// Indicates that the provided string does not contain any valid IpNetwork.
    NotValidIPNetwork(String),
}

impl std::fmt::Display for MechanismError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MechanismError::NotValidMechanismFormat(mesg) => {
                write!(f, "{} does not conform to any Mechanism format.", mesg)
            }
            MechanismError::NotIP4Network(mesg) => {
                write!(f, "Was given ip4:{}. This is not an ip4 network.", mesg)
            }
            MechanismError::NotIP6Network(mesg) => {
                write!(f, "Was given ip6:{}. This is not an ip6 network.", mesg)
            }
            MechanismError::NotValidIPNetwork(mesg) => {
                write!(f, "{}.", mesg)
            }
        }
    }
}
/// simethuing
impl MechanismError {
    /// Returns `true` if it is not a valid Mechanism format.
    pub fn is_invalid_format(&self) -> bool {
        matches!(self, Self::NotValidMechanismFormat(_))
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
    /// Return `true` if it the string can not be parsed to and IpNetwork
    /// # Example:
    /// "ip4:203.32.160.0/33" would give this error. This applies to IP6 networks.
    pub fn is_invalid_ip(&self) -> bool {
        matches!(self, Self::NotValidIPNetwork(_))
    }
}

impl std::error::Error for MechanismError {}
