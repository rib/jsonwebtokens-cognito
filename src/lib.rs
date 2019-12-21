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
            min_jwks_fetch_interval: Duration::from_secs(60 * 5),
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

    pub fn min_jwks_fetch_interval(&mut self, interval: Duration) {
        self.min_jwks_fetch_interval = interval;
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

    fn try_cache_fetch_algorithm(&self, kid: &str) -> Result<(Option<Arc<Algorithm>>, Option<Instant>), Error> {

        // We unwrap, because poisoning would imply something else had gone
        // badly wrong (there should be nothing that can cause a panic while
        // holding the cache's lock)
        let readable_cache = self.cache.read().unwrap();

        let a = readable_cache.algorithms.get(kid);
        if let Some(alg) = a {
            Ok((Some(alg.clone()), readable_cache.last_jwks_get_time))
        } else {
            Ok((None, readable_cache.last_jwks_get_time))
        }
    }

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

        let algorithm = match self.try_cache_fetch_algorithm(kid)? {
            (None, last_update_time) => {
                let duration = match last_update_time {
                    Some(last_jwks_get_time) => Instant::now().duration_since(last_jwks_get_time),
                    None => self.min_jwks_fetch_interval
                };

                if duration < self.min_jwks_fetch_interval {
                    return Err(Error::NetworkError(ErrorDetails::new("Key set is currently unreachable (throttled)")))
                }

                self.prefetch_jwks().await?;
                match self.try_cache_fetch_algorithm(kid)? {
                    (None, _) => return Err(Error::NetworkError(ErrorDetails::new("Failed to get key set"))),
                    (Some(a), _) => a
                }
            },
            (Some(a), _) => a
        };

        let claims = verifier.verify(token, &algorithm)?;
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
