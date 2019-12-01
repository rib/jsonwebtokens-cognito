A minimal library to handle verifying a JWT token against an AWS Cognito JWKS key set

# Install

```
cognito-jws = "0.1"
```

# Usage

```rust
let keyset = KeySet::new("eu-west-1", "my-user-pool-id");
let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
    .claim_equals("custom_claim0", "value")
    .claim_equals("custom_claim1", "value")
    .build();

let claims: MyClaims = keyset.verify(token, verifier).await?;
```

This library builds on top of [jwt-rust](https://github.com/rib/jwt-rust)
token verifiers.

The keyset will lazily fetch from the appropriate .jwks url when verifying
the first token or, alternatively the cache can be primed by calling
`keyset.get_jwks()`.

The keyset is Send safe so it can be used for authentication within a
multi-threaded server. The key caching is handled with interior mutability
so you don't need to hold a mutable reference to the keyset when
validating a token.
