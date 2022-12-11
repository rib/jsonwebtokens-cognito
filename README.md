A Rust library for verifying Json Web Tokens issued by AWS Cognito

# Install

```
jsonwebtokens-cognito = "0.1.0-alpha"
```

# Usage

```rust
let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
    .string_equals("custom_claim0", "value")
    .string_equals("custom_claim1", "value")
    .build()?;

let claims = keyset.verify(token, &verifier).await?;
```

This library builds on top of [jsonwebtokens](https://crates.io/crate/jsonwebtokens)
token verifiers.

The keyset will fetch from the appropriate .jwks url when verifying the first
token or, alternatively the cache can be primed by calling
`keyset.prefetch_jwks()`:

```rust
let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
keyset.prefetch_jwks().await?;
```

If you need to perform token verification in a non-async context, or don't
wan't to allow network I/O while verifying tokens then if you have explicitly
prefetched the jwks key set you can verify tokens with `try_verify`:

```rust
let keyset = KeySet::new("eu-west-1", "my-user-pool-id")?;
keyset.prefetch_jwks().await?;
let verifier = keyset.new_id_token_verifier(&["client-id-0", "client-id-1"])
    .string_equals("custom_claim0", "value")
    .string_equals("custom_claim1", "value")
    .build()?;

let claims = keyset.try_verify(token, verifier).await?;
```

_try_verify() will return a CacheMiss error if the required key has not been
prefetched_

A Keyset is Send safe so it can be used for authentication within a
multi-threaded server.

# Examples

## Verify an AWS Cognito Access token

```rust
let keyset = KeySet::new(AWS_REGION, AWS_POOL_ID)?;
let verifier = keyset.new_access_token_verifier(&[AWS_CLIENT_ID]).build()?;

keyset.verify(&token_str, &verifier).await?;
```

## Verify an AWS Cognito Identity token

```rust
let keyset = KeySet::new(AWS_REGION, AWS_POOL_ID)?;
let verifier = keyset.new_id_token_verifier(&[AWS_CLIENT_ID]).build()?;

keyset.verify(&token_str, &verifier).await?;
```

## Verify an AWS Cognito Access token with custom claims

```rust
let keyset = KeySet::new(AWS_REGION, AWS_POOL_ID)?;
let verifier = keyset.new_access_token_verifier(&[AWS_CLIENT_ID])
    .string_equals("my_claim", "foo")
    .build()?;

keyset.verify(&token_str, &verifier).await?;
```

See [jsonwebtokens](https://crates.io/crates/jsonwebtokens#user-content-verifying-standard-claims) for more examples
of how to verify custom claims.
