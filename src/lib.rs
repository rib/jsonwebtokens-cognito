use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use serde::{Deserialize};
use serde_json::value::Value;
use serde_json;

use reqwest::{self, Response};

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier, VerifierBuilder};

mod error;
pub use error::{Error, ErrorDetails};

#[derive(Debug, Deserialize, Clone)]
struct RSAKey {
    kid: String,
    alg: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<RSAKey>,
}

#[derive(Debug, Clone)]
struct Cache {
    last_jwks_get_time: Option<Instant>,
    algorithms: HashMap<String, Arc<Algorithm>>,
}

/// Abstracts a remote Amazon Cognito JWKS key set
///
/// The key set represents the public key information for one or more RSA keys that
/// Amazon Cognito uses to sign tokens. To verify a token from Cognito the token's
/// `kid` is used to look up the corresponding public key from this set which can
/// be used to verify the token's signature.
///
/// Building on top of the [Verifier](https://docs.rs/jsonwebtokens/1.0.0-alpha.8/jsonwebtokens/struct.Verifier.html)
/// API from [jsonwebtokens](https://crates.io/crates/jsonwebtokens), a KeySet provides some
/// helpers for building a [Verifier](https://docs.rs/jsonwebtokens/1.0.0-alpha.8/jsonwebtokens/struct.Verifier.html)
/// for Cognito Access token claims or ID token claims - referencing the region and
/// pool details used to construct the keyset.
///
/// Example:
/// ```no_run
/// # use jsonwebtokens_cognito::KeySet;
/// # use async_std::prelude::*;
/// # #[async_std::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
/// let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
///     .claim_equals("custom_claim0", "value")
///     .claim_equals("custom_claim1", "value")
///     .build()?;
/// # let token = "header.payload.signature";
/// let claims = keyset.verify(token, &verifier).await?;
/// # Ok(())
/// # }
/// ```
///
/// Internally a KeySet holds a cache of Algorithm structs (see the jsonwebtokens
/// API for further details) where each Algorithm represents one RSA public key.
///
/// Although `keyset.verify()` can be very convenient, if you need to avoid network
/// I/O when verifying tokens it's also possible to prefetch the remote JWKS key
/// set ahead of time and `try_verify()` can be used to verify a token without any
/// network I/O. This can be useful if you don't have an async context when
/// verifying tokens.
///
/// ```no_run
/// # use jsonwebtokens_cognito::KeySet;
/// # use async_std::prelude::*;
/// # #[async_std::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
/// keyset.prefetch_jwks().await?;
/// let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
///     .claim_equals("custom_claim0", "value")
///     .claim_equals("custom_claim1", "value")
///     .build()?;
/// # let token = "header.payload.signature";
/// let claims = keyset.try_verify(token, &verifier)?;
/// # Ok(())
/// # }
/// ```
///
/// It's also possible to perform cache lookups directly to access an Algorithm if
/// you need to use the jsonwebtokens API directly:
/// ```no_run
/// # use jsonwebtokens_cognito::KeySet;
/// # use jsonwebtokens as jwt;
/// # use serde_json::value::Value;
/// # use async_std::prelude::*;
/// # #[async_std::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "header.payload.signature";
/// let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
/// keyset.prefetch_jwks().await?;
///
/// let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
///     .claim_equals("custom_claim0", "value")
///     .claim_equals("custom_claim1", "value")
///     .build()?;
///
/// let header = jwt::raw::decode_header_only(token)?;
/// if let Some(Value::String(kid)) = header.get("kid") {
///     let alg = keyset.try_cache_lookup_algorithm(kid)?;
///     let claims = verifier.verify(token, &alg)?;
///
///     // Whoop!
/// } else {
///     Err(jwt::error::Error::MalformedToken(jwt::error::ErrorDetails::new("Missing kid")))?;
/// };
/// # Ok(())
/// # }
/// ```

///
#[derive(Debug, Clone)]
pub struct KeySet {
    region: String,
    pool_id: String,
    jwks_url: String,
    iss: String,
    cache: Arc<RwLock<Cache>>,
    min_jwks_fetch_interval: Duration,
}

impl KeySet {

    /// Constructs a key set that corresponds to a remote Json Web Key Set published
    /// by Amazon for a given region and Cognito User Pool ID.
    pub fn new(region: impl Into<String>,
               pool_id: impl Into<String>
    ) -> Result<Self, Error> {

        let region_str = region.into();
        let pool_id_str = pool_id.into();
        let jwks_url = format!("https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
                                       region_str, pool_id_str).into();
        let iss = format!("https://cognito-idp.{}.amazonaws.com/{}", region_str, pool_id_str);

        Ok(KeySet {
            region: region_str,
            pool_id: pool_id_str,
            jwks_url: jwks_url,
            iss: iss,
            cache: Arc::new(RwLock::new(Cache {
                last_jwks_get_time: None,
                algorithms: HashMap::new()
            })),
            min_jwks_fetch_interval: Duration::from_secs(60),
        })
    }

    /// Returns a `VerifierBuilder` that has been pre-configured to validate an
    /// AWS Cognito ID token. This can be further configured for verifying other
    /// custom claims before calling `.build()` to create a `Verifier`
    pub fn new_id_token_verifier(&self, client_ids: &[&str]) -> VerifierBuilder {
        let mut builder = Verifier::create();

        builder
            .claim_equals("iss", &self.iss)
            .claim_equals_one_of("aud", client_ids)
            .claim_equals("token_use", "id");

        builder
    }

    /// Set's the minimum time between attempts to fetch the remote JWKS key set
    ///
    /// By default this is one minute, to throttle requests in case there is a
    /// transient network problem
    pub fn set_min_jwks_fetch_interval(&mut self, interval: Duration) {
        self.min_jwks_fetch_interval = interval;
    }

    /// Get's the minimum time between attempts to fetch the remote JWKS key set
    pub fn min_jwks_fetch_interval(&mut self) -> Duration {
        self.min_jwks_fetch_interval
    }

    /// Returns a `VerifierBuilder` that has been pre-configured to validate an
    /// AWS Cognito access token. This can be further configured for verifying other
    /// custom claims before calling `.build()` to create a `Verifier`
    pub fn new_access_token_verifier(&self, client_ids: &[&str]) -> VerifierBuilder {
        let mut builder = Verifier::create();

        builder
            .claim_equals("iss", &self.iss)
            .claim_equals_one_of("client_id", client_ids)
            .claim_equals("token_use", "access");

        builder
    }

    /// Looks for a cached Algorithm based on the given JWT token's key ID ('kid')
    ///
    /// This is a lower-level API in case you need to use the jsonwebtokens
    /// Algorithm API directly.
    ///
    /// Returns an `Arc<Algorithm>` corresponding to the give key ID (`kid`) or returns
    /// a `CacheMiss` error if the Algorithm / key is not cached.
    pub fn try_cache_lookup_algorithm(&self, kid: &str) -> Result<Arc<Algorithm>, Error> {

        // We unwrap, because poisoning would imply something else had gone
        // badly wrong (there should be nothing that can cause a panic while
        // holding the cache's lock)
        let readable_cache = self.cache.read().unwrap();

        let a = readable_cache.algorithms.get(kid);
        if let Some(alg) = a {
            return Ok(alg.clone());
        } else {
            return Err(Error::CacheMiss(readable_cache.last_jwks_get_time));
        }
    }

    /// Verify a token's signature and its claims
    pub async fn verify(
        &self,
        token: &str,
        verifier: &Verifier
    ) -> Result<serde_json::value::Value, Error> {

        let header = jwt::raw::decode_header_only(token)?;

        let kid = match header.get("kid") {
            Some(Value::String(kid)) => kid,
            _ => return Err(Error::NoKeyID()),
        };

        let algorithm = match self.try_cache_lookup_algorithm(kid) {
            Err(Error::CacheMiss(last_update_time)) => {
                let duration = match last_update_time {
                    Some(last_jwks_get_time) => Instant::now().duration_since(last_jwks_get_time),
                    None => self.min_jwks_fetch_interval
                };

                if duration < self.min_jwks_fetch_interval {
                    return Err(Error::NetworkError(ErrorDetails::new("Key set is currently unreachable (throttled)")))
                }

                self.prefetch_jwks().await?;
                self.try_cache_lookup_algorithm(kid)?
            },
            Err(e) => {
                // try_cache_lookup_algorithm shouldn't return any other kind of error...
                unreachable!("Unexpected error looking up JWT Algorithm for key ID: {:?}", e);
            }
            Ok(alg) => alg
        };

        let claims = verifier.verify(token, &algorithm)?;
        Ok(claims)
    }

    /// Try and verify a token's signature and claims without performing any network I/O
    ///
    /// To be able to verify a token in a synchronous context (but without blocking) this
    /// API lets you try and verify a token, and if the required Algorithm / key has not
    /// been cached yet then it will return a `CacheMiss` error.
    pub fn try_verify(
        &self,
        token: &str,
        verifier: &Verifier
    ) -> Result<serde_json::value::Value, Error> {

        let header = jwt::raw::decode_header_only(token)?;

        let kid = match header.get("kid") {
            Some(Value::String(kid)) => kid,
            _ => return Err(Error::NoKeyID()),
        };

        let alg = self.try_cache_lookup_algorithm(kid)?;
        let claims = verifier.verify(token, &alg)?;
        Ok(claims)
    }

    /// Ensure the remote Json Web Key Set is downloaded and cached
    pub async fn prefetch_jwks(&self) -> Result<(), Error> {
        let resp: Response = reqwest::get(&self.jwks_url).await?;
        let jwks: JwkSet = resp.json().await?;

        // We unwrap, because poisoning would imply something else had gone
        // badly wrong (there should be nothing that can cause a panic while
        // holding the cache's lock)
        let mut writeable_cache = self.cache.write().unwrap();

        writeable_cache.last_jwks_get_time = Some(Instant::now());

        for key in jwks.keys.into_iter() {
            // For now we assume AWS Cognito only ever uses RS256 keys
            if key.alg != "RS256" {
                continue;
            }
            let mut algorithm = Algorithm::new_rsa_n_e_b64_verifier(AlgorithmID::RS256, &key.n, &key.e)?;
            // By associating a kid here we will essentially be double checking
            // that we only verify a token with the key matching its associated kid
            // (once by us and jsonwebtokens will also check too)
            algorithm.set_kid(&key.kid);
            writeable_cache.algorithms.insert(key.kid.clone(), Arc::new(algorithm));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
