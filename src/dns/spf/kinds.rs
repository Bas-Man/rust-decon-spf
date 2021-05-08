/// Defines the supported SPF Mechanicms
#[derive(Debug, Clone)]
pub enum MechanismKind {
    /// Represents a Mechanism of type include:
    Include,
    /// Represents a Mechanism of type redirect=
    Redirect,
    /// Represents a Mechanism of type a
    A,
    /// Represents a Mechanism of type mx
    MX,
    /// Represents a Mechanism of type ip4:
    IpV4,
    /// Represents a Mechanism of type ip6:
    IpV6,
    /// Represents a Mechanism of type all
    All,
}

impl MechanismKind {
    /// Returns `true` if the mechanism is [`Include`](MechanismKind::Include).
    pub fn is_include(&self) -> bool {
        matches!(self, Self::Include)
    }
    /// Returns `true` if the mechanism is [`A`](MechanismKind::A).
    pub fn is_a(&self) -> bool {
        matches!(self, Self::A)
    }

    /// Returns `true` if the mechanism is [`MX`](MechanismKind::MX).
    pub fn is_mx(&self) -> bool {
        matches!(self, Self::MX)
    }

    /// Returns `true` if the mechanism is [`IpV4`](MechanismKind::IpV4).
    pub fn is_ip_v4(&self) -> bool {
        matches!(self, Self::IpV4)
    }

    /// Returns `true` if the mechanism is [`IpV6`](MechanismKind::IpV6).
    pub fn is_ip_v6(&self) -> bool {
        matches!(self, Self::IpV6)
    }

    /// Returns `true` if the mechanism is [`All`](MechanismKind::All).
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns `true` if the mechanism is [`Redirect`](MechanismKind::Redirect).
    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
}

impl Default for MechanismKind {
    fn default() -> Self {
        Self::Include
    }
}
