use std::error::Error as StdError;
use std::fmt;
use std::time::Instant;

use jsonwebtokens as jwt;
use jwt::error::Error as JwtError;

#[derive(Debug)]
pub struct ErrorDetails {
    desc: String,
    src: Option<Box<dyn StdError + Send>>,

    #[doc(hidden)]
    _extensible: (),
}

impl ErrorDetails {
    pub fn new(desc: impl Into<String>) -> ErrorDetails {
        ErrorDetails {
            desc: desc.into(),
            src: None,
            _extensible: ()
        }
    }

    pub fn map<T: 'static + StdError + Send>(desc: impl Into<String>, src: T) -> ErrorDetails {
        ErrorDetails {
            desc: desc.into(),
            src: Some(Box::new(src)),
            _extensible: ()
        }
    }
}

impl From<String> for ErrorDetails {
    fn from(s: String) -> Self {
        ErrorDetails {
            desc: s,
            src: None,
            _extensible: ()
        }
    }
}

#[derive(Debug)]
pub enum Error {

    /// The token header didn't have a 'kid' key ID value
    NoKeyID(),

    /// The token's signature is invalid
    InvalidSignature(),

    /// The token expired at this time (unix epoch timestamp)
    TokenExpiredAt(u64),

    /// Any of: header.payload.signature split error, json parser error, header or claim validation error
    MalformedToken(ErrorDetails),

    /// Failed to fetch remote jwks key set
    NetworkError(ErrorDetails),

    /// try_verify() failed because the required Algorithm/key wasn't cached
    ///
    /// The included Instant indicates when the cache was last updated (if not None)
    CacheMiss(Option<Instant>),

    #[doc(hidden)]
    __Nonexhaustive
}

impl StdError for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::NoKeyID() => write!(f, "Token had no 'kid' value"),
            Error::InvalidSignature() => write!(f, "JWT Signature Invalid"),
            Error::TokenExpiredAt(when) => write!(f, "JWT token expired at {}", when),
            Error::MalformedToken(details) => {
                match &details.src {
                    Some(src) => src.fmt(f),
                    None => write!(f, "JWT claims invalid: {}", details.desc),
                }
            }
            Error::NetworkError(details) => write!(f, "Error fetching JWKS key set: {}", details.desc),
            Error::CacheMiss(_) => write!(f, "Failed to lookup corresponding Algorithm / key"),
            Error::__Nonexhaustive => { write!(f, "Unknown error") }
        }
    }
}

impl From<jwt::error::Error> for Error {
    fn from(e: jwt::error::Error) -> Self {
        match e {
            JwtError::InvalidSignature() => Error::InvalidSignature(),
            JwtError::TokenExpiredAt(when) => Error::TokenExpiredAt(when),
            JwtError::MalformedToken(_) => Error::MalformedToken(ErrorDetails::map("Malformed JWT", e)),
            JwtError::AlgorithmMismatch() => Error::MalformedToken(ErrorDetails::map("Unexpected 'alg' algorithm specified", e)),
            _ => Error::MalformedToken(ErrorDetails::map("Decode failure", e)),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::NetworkError(ErrorDetails::map("Reqwest error", e))
    }
}
