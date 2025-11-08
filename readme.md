## argon2-rs

A very simple crate for hashing passwords with the Argon2 algorithm.

This crate is using the original [C implementation](https://github.com/P-H-C/phc-winner-argon2) of Argon2.

## Example

```rust
use argon2_rs::Argon2;

let argon2 = Argon2::balanced();
let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
let hash = argon2.hash_password("password", salt).unwrap();
assert_eq!(hash.len(), 64);
```

## Features

- `zeroize` - Zeroizes the salt after hashing.