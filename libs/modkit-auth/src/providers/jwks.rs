use crate::{claims_error::ClaimsError, plugin_traits::KeyProvider, types::JwtHeader};
use aliri::jwt::{BasicHeaders, CoreHeaders, HasAlgorithm};
use aliri::{Jwks, JwtRef, jwt};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

/// JWKS-based key provider using aliri
///
/// Provides JWT validation with background key refresh and on-demand refresh for unknown keys.
#[must_use]
pub struct JwksKeyProvider {
    /// JWKS endpoint URL
    jwks_uri: String,

    /// Cached JWKS
    jwks: Arc<RwLock<Option<Jwks>>>,

    /// Last refresh time tracking
    refresh_state: Arc<RwLock<RefreshState>>,

    /// HTTP client for fetching JWKS
    client: reqwest::Client,

    /// Refresh interval (default: 5 minutes)
    refresh_interval: Duration,

    /// Maximum backoff duration (default: 1 hour)
    max_backoff: Duration,

    /// Cooldown for on-demand refresh (default: 60 seconds)
    on_demand_refresh_cooldown: Duration,
}

#[derive(Debug, Default)]
struct RefreshState {
    last_refresh: Option<Instant>,
    last_on_demand_refresh: Option<Instant>,
    consecutive_failures: u32,
    last_error: Option<String>,
}

impl JwksKeyProvider {
    /// Create a new JWKS key provider
    ///
    /// # Errors
    /// Returns an error if the HTTP client fails to build.
    pub fn new(jwks_uri: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            jwks_uri: jwks_uri.into(),
            jwks: Arc::new(RwLock::new(None)),
            refresh_state: Arc::new(RwLock::new(RefreshState::default())),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
            refresh_interval: Duration::from_secs(300), // 5 minutes
            max_backoff: Duration::from_secs(3600),     // 1 hour
            on_demand_refresh_cooldown: Duration::from_secs(60), // 1 minute
        })
    }

    /// Create with custom refresh interval
    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Create with custom max backoff
    #[must_use]
    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    /// Create with custom on-demand refresh cooldown
    #[must_use]
    pub fn with_on_demand_refresh_cooldown(mut self, cooldown: Duration) -> Self {
        self.on_demand_refresh_cooldown = cooldown;
        self
    }

    /// Fetch JWKS from the endpoint
    async fn fetch_jwks(&self) -> Result<Jwks, ClaimsError> {
        let response = self
            .client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| ClaimsError::JwksFetchFailed(format!("HTTP request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ClaimsError::JwksFetchFailed(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| ClaimsError::JwksFetchFailed(format!("Failed to parse JWKS: {e}")))?;

        Ok(jwks)
    }

    /// Calculate backoff duration based on consecutive failures
    fn calculate_backoff(&self, failures: u32) -> Duration {
        let base = Duration::from_secs(60); // 1 minute base
        let exponential = base * 2u32.pow(failures.min(10)); // Cap at 2^10
        exponential.min(self.max_backoff)
    }

    /// Check if refresh is needed based on interval and backoff
    async fn should_refresh(&self) -> bool {
        let state = self.refresh_state.read().await;

        match state.last_refresh {
            None => true, // Never refreshed
            Some(last) => {
                let elapsed = last.elapsed();
                if state.consecutive_failures == 0 {
                    // Normal refresh interval
                    elapsed >= self.refresh_interval
                } else {
                    // Exponential backoff
                    elapsed >= self.calculate_backoff(state.consecutive_failures)
                }
            }
        }
    }

    /// Perform key refresh with error tracking
    async fn perform_refresh(&self) -> Result<(), ClaimsError> {
        match self.fetch_jwks().await {
            Ok(new_jwks) => {
                // Update keys
                {
                    let mut jwks_guard = self.jwks.write().await;
                    *jwks_guard = Some(new_jwks);
                }

                // Update refresh state
                let mut state = self.refresh_state.write().await;
                state.last_refresh = Some(Instant::now());
                state.consecutive_failures = 0;
                state.last_error = None;

                Ok(())
            }
            Err(e) => {
                // Update failure state
                let mut state = self.refresh_state.write().await;
                state.last_refresh = Some(Instant::now());
                state.consecutive_failures += 1;
                state.last_error = Some(e.to_string());

                Err(e)
            }
        }
    }

    /// Check if we're in cooldown period and handle throttling logic
    async fn check_refresh_throttle(&self, kid: &str) -> Result<(), ClaimsError> {
        let state = self.refresh_state.read().await;
        if let Some(last_on_demand) = state.last_on_demand_refresh {
            let elapsed = last_on_demand.elapsed();
            if elapsed < self.on_demand_refresh_cooldown {
                let remaining = self.on_demand_refresh_cooldown.saturating_sub(elapsed);
                tracing::debug!(
                    kid = kid,
                    remaining_secs = remaining.as_secs(),
                    "On-demand JWKS refresh throttled (cooldown active)"
                );
                return Err(ClaimsError::UnknownKeyId(kid.to_owned()));
            }
        }
        Ok(())
    }

    /// Try to refresh keys if unknown kid is encountered
    async fn on_demand_refresh(&self, kid: &str) -> Result<(), ClaimsError> {
        // Check if we're in cooldown period
        self.check_refresh_throttle(kid).await?;

        tracing::info!(
            kid = kid,
            "Performing on-demand JWKS refresh for unknown kid"
        );

        // Attempt refresh
        match self.perform_refresh().await {
            Ok(()) => {
                let mut state = self.refresh_state.write().await;
                state.last_on_demand_refresh = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                let mut state = self.refresh_state.write().await;
                state.last_on_demand_refresh = Some(Instant::now());
                Err(e)
            }
        }
    }

    /// Validate JWT using aliri and return header + claims
    async fn validate_jwt_internal(&self, token: &str) -> Result<(JwtHeader, Value), ClaimsError> {
        // Parse the JWT
        let jwt = JwtRef::from_str(token);

        // Decompose to get header info using BasicHeaders (which implements CoreHeaders + HasAlgorithm)
        let decomposed: jwt::Decomposed<'_, BasicHeaders> = jwt
            .decompose()
            .map_err(|e| ClaimsError::DecodeFailed(format!("Failed to decompose JWT: {e}")))?;

        // Extract header info using trait methods
        let kid = decomposed.kid().map(ToString::to_string);
        let alg = decomposed.alg();
        let algorithm_str = format!("{alg:?}");

        // Extract kid for key lookup
        let kid_str = kid
            .as_ref()
            .ok_or_else(|| ClaimsError::DecodeFailed("Missing kid in JWT header".into()))?;

        // Get JWKS - if not loaded, trigger refresh
        {
            let jwks_guard = self.jwks.read().await;
            if jwks_guard.is_none() {
                drop(jwks_guard);
                self.on_demand_refresh(kid_str).await?;
            }
        }

        // Try to verify with current keys
        let verify_result: Result<jwt::Validated<jwt::BasicClaims, BasicHeaders>, ClaimsError> = {
            let jwks_guard = self.jwks.read().await;
            let jwks = jwks_guard
                .as_ref()
                .ok_or_else(|| ClaimsError::JwksFetchFailed("No JWKS loaded".into()))?;

            // Find the key by ID using the decomposed header's kid
            let key = jwks
                .get_key_by_opt(decomposed.kid(), alg)
                .ok_or_else(|| ClaimsError::UnknownKeyId(kid_str.clone()))?;

            // Create a validator that skips time validation (we do it separately)
            let validator = jwt::CoreValidator::default()
                .ignore_expiration()
                .ignore_not_before()
                .add_approved_algorithm(alg);

            // Verify the JWT with BasicClaims (which implements CoreClaims)
            jwt.verify::<jwt::BasicClaims, BasicHeaders, _>(key, &validator)
                .map_err(|e| ClaimsError::DecodeFailed(format!("JWT validation failed: {e}")))
        };

        // If key not found, try refresh once
        let _validated = match verify_result {
            Ok(v) => v,
            Err(ClaimsError::UnknownKeyId(_)) => {
                // Try on-demand refresh
                self.on_demand_refresh(kid_str).await?;

                // Retry verification
                let jwks_guard = self.jwks.read().await;
                let jwks = jwks_guard
                    .as_ref()
                    .ok_or_else(|| ClaimsError::JwksFetchFailed("No JWKS loaded".into()))?;

                // Re-decompose to get fresh reference
                let decomposed: jwt::Decomposed<'_, BasicHeaders> =
                    jwt.decompose().map_err(|e| {
                        ClaimsError::DecodeFailed(format!("Failed to decompose JWT: {e}"))
                    })?;

                let key = jwks
                    .get_key_by_opt(decomposed.kid(), decomposed.alg())
                    .ok_or_else(|| ClaimsError::UnknownKeyId(kid_str.clone()))?;

                let validator = jwt::CoreValidator::default()
                    .ignore_expiration()
                    .ignore_not_before()
                    .add_approved_algorithm(alg);

                jwt.verify::<jwt::BasicClaims, BasicHeaders, _>(key, &validator)
                    .map_err(|e| ClaimsError::DecodeFailed(format!("JWT validation failed: {e}")))?
            }
            Err(e) => return Err(e),
        };

        // Now parse the payload as Value for full claims
        // The JWT is verified, so we can safely decode the payload
        let payload = decomposed.untrusted_payload();
        let claims: Value = serde_json::from_str(payload)
            .map_err(|e| ClaimsError::DecodeFailed(format!("Failed to parse claims: {e}")))?;

        let jwt_header = JwtHeader::new(algorithm_str, kid);

        Ok((jwt_header, claims))
    }
}

#[async_trait]
impl KeyProvider for JwksKeyProvider {
    fn name(&self) -> &'static str {
        "jwks"
    }

    async fn validate_and_decode(&self, token: &str) -> Result<(JwtHeader, Value), ClaimsError> {
        // Strip "Bearer " prefix if present
        let token = token.trim_start_matches("Bearer ").trim();
        self.validate_jwt_internal(token).await
    }

    async fn refresh_keys(&self) -> Result<(), ClaimsError> {
        if self.should_refresh().await {
            self.perform_refresh().await
        } else {
            Ok(())
        }
    }
}

/// Background task to periodically refresh JWKS
pub async fn run_jwks_refresh_task(provider: Arc<JwksKeyProvider>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60)); // Check every minute

    loop {
        interval.tick().await;

        if let Err(e) = provider.refresh_keys().await {
            tracing::warn!("JWKS refresh failed: {}", e);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_backoff() -> Result<(), reqwest::Error> {
        let provider = JwksKeyProvider::new("https://example.com/jwks")?;

        assert_eq!(provider.calculate_backoff(0), Duration::from_secs(60));
        assert_eq!(provider.calculate_backoff(1), Duration::from_secs(120));
        assert_eq!(provider.calculate_backoff(2), Duration::from_secs(240));
        assert_eq!(provider.calculate_backoff(3), Duration::from_secs(480));

        // Should cap at max_backoff
        assert_eq!(provider.calculate_backoff(100), provider.max_backoff);
        Ok(())
    }

    #[tokio::test]
    async fn test_should_refresh_on_first_call() -> Result<(), reqwest::Error> {
        let provider = JwksKeyProvider::new("https://example.com/jwks")?;
        assert!(provider.should_refresh().await);
        Ok(())
    }

    #[tokio::test]
    async fn test_on_demand_refresh_returns_error_for_failed_fetch() -> Result<(), reqwest::Error> {
        let provider =
            JwksKeyProvider::new("https://invalid-domain-that-does-not-exist.local/jwks")?;

        // Attempting to refresh should fail (network error)
        let result = provider.on_demand_refresh("missing-kid").await;
        assert!(result.is_err());

        // The error should be related to fetch failure
        match result.expect_err("expected error for missing key") {
            ClaimsError::JwksFetchFailed(_) | ClaimsError::UnknownKeyId(_) => {}
            other => panic!("Expected JwksFetchFailed or UnknownKeyId, got: {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_on_demand_refresh_respects_cooldown() -> Result<(), reqwest::Error> {
        let provider = JwksKeyProvider::new("https://invalid-domain.local/jwks")?
            .with_on_demand_refresh_cooldown(Duration::from_secs(5));

        // First attempt - should try to refresh
        let result1 = provider.on_demand_refresh("test-kid").await;
        assert!(result1.is_err()); // Will fail due to invalid domain

        // Immediate second attempt - should be throttled
        let result2 = provider.on_demand_refresh("test-kid").await;
        assert!(result2.is_err());

        // Should return UnknownKeyId due to cooldown
        match result2.expect_err("expected throttle error") {
            ClaimsError::UnknownKeyId(_) => {}
            other => panic!("Expected UnknownKeyId during cooldown, got: {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_perform_refresh_updates_state_on_failure() -> Result<(), reqwest::Error> {
        let provider = JwksKeyProvider::new("https://invalid-domain.local/jwks")?;

        // Mark as previously failed
        {
            let mut state = provider.refresh_state.write().await;
            state.consecutive_failures = 3;
            state.last_error = Some("Previous error".to_owned());
        }

        // This will fail
        let res = provider.perform_refresh().await;
        assert!(res.is_err());

        // Check that consecutive_failures increased
        let state = provider.refresh_state.read().await;
        assert_eq!(state.consecutive_failures, 4);
        assert!(state.last_error.is_some());
        Ok(())
    }
}
