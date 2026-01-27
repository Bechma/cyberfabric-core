/// JWT header information (library-agnostic abstraction)
///
/// This struct provides a stable interface for JWT header data,
/// decoupling consumers from the underlying JWT library implementation.
#[derive(Debug, Clone, Default)]
pub struct JwtHeader {
    /// Key identifier (kid) from the JWT header
    pub kid: Option<String>,
    /// Algorithm used for signing (e.g., "RS256")
    pub algorithm: String,
}

impl JwtHeader {
    /// Create a new `JwtHeader` with the given algorithm and optional kid
    #[must_use]
    pub fn new(algorithm: impl Into<String>, kid: Option<String>) -> Self {
        Self {
            kid,
            algorithm: algorithm.into(),
        }
    }

    /// Create a `JwtHeader` for RS256 algorithm
    #[must_use]
    pub fn rs256(kid: Option<String>) -> Self {
        Self::new("RS256", kid)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let header = JwtHeader::default();
        assert!(header.kid.is_none());
        assert!(header.algorithm.is_empty());
    }

    #[test]
    fn test_new() {
        let header = JwtHeader::new("RS256", Some("key-1".to_owned()));
        assert_eq!(header.algorithm, "RS256");
        assert_eq!(header.kid, Some("key-1".to_owned()));
    }

    #[test]
    fn test_rs256() {
        let header = JwtHeader::rs256(Some("key-2".to_owned()));
        assert_eq!(header.algorithm, "RS256");
        assert_eq!(header.kid, Some("key-2".to_owned()));
    }
}
