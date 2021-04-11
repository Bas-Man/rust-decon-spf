#[derive(Debug, Clone)]
pub enum MechanismKind {
    Include,
    Redirect,
    A,
    MX,
    IpV4,
    IpV6,
    All,
}

impl MechanismKind {
    /// Returns `true` if the mechanism_kind is [`Include`].
    pub fn is_include(&self) -> bool {
        matches!(self, Self::Include)
    }
    /// Returns `true` if the mechanism_kind is [`A`].
    pub fn is_a(&self) -> bool {
        matches!(self, Self::A)
    }

    /// Returns `true` if the mechanism_kind is [`MX`].
    pub fn is_mx(&self) -> bool {
        matches!(self, Self::MX)
    }

    /// Returns `true` if the mechanism_kind is [`IpV4`].
    pub fn is_ip_v4(&self) -> bool {
        matches!(self, Self::IpV4)
    }

    /// Returns `true` if the mechanism_kind is [`IpV6`].
    pub fn is_ip_v6(&self) -> bool {
        matches!(self, Self::IpV6)
    }

    /// Returns `true` if the mechanism_kind is [`All`].
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Returns `true` if the mechanism_kind is [`Redirect`].
    pub fn is_redirect(&self) -> bool {
        matches!(self, Self::Redirect)
    }
}

impl Default for MechanismKind {
    fn default() -> Self {
        Self::Include
    }
}
