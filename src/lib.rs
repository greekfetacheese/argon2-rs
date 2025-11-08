pub mod error;
use error::*;

use argon2_sys::{ARGON2_DEFAULT_FLAGS, argon2_context, argon2_ctx};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub const RECOMMENDED_HASH_LENGTH: u64 = 64;

/// Argon2 primitive type: variants of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Default, Ord)]
pub enum Algorithm {
    /// Optimizes against GPU cracking attacks but vulnerable to side-channels.
    ///
    /// Accesses the memory array in a password dependent order, reducing the
    /// possibility of time–memory tradeoff (TMTO) attacks.
    Argon2d = 0,

    /// Optimized to resist side-channel attacks.
    ///
    /// Accesses the memory array in a password independent order, increasing the
    /// possibility of time-memory tradeoff (TMTO) attacks.
    Argon2i = 1,

    /// Hybrid that mixes Argon2i and Argon2d passes (*default*).
    ///
    /// Uses the Argon2i approach for the first half pass over memory and
    /// Argon2d approach for subsequent passes. This effectively places it in
    /// the "middle" between the other two: it doesn't provide as good
    /// TMTO/GPU cracking resistance as Argon2d, nor as good of side-channel
    /// resistance as Argon2i, but overall provides the most well-rounded
    /// approach to both classes of attacks.
    #[default]
    Argon2id = 2,
}

/// Version of the algorithm.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Version {
    /// Version 16 (0x10 in hex)
    ///
    /// Performs overwrite internally
    V0x10 = 0x10,

    /// Version 19 (0x13 in hex, default)
    ///
    /// Performs XOR internally
    #[default]
    V0x13 = 0x13,
}

/// Argon2 instance
///
/// # Parameters
///
/// - `m_cost` - The memory cost in kibibytes
/// - `t_cost` - Iteration cost
/// - `p_cost` - Parallelization
/// - `hash_length` - The length of the hash in bytes
/// - `algorithm` - The algorithm to use
/// - `version` - The version of the algorithm to use
///
/// By default it will use the `Argon2id` with a `64 byte` hash length (maximum).
/// 
/// It is not recomended to change them, the default values are fine for most use cases.
///
/// Generally speaking you don't want to mess with the `t_cost` and `p_cost` parameters a lot.
/// For max security the `p_cost` should be set to `1` and the `t_cost` could be anything between `8` and `30`.
/// That also depends on the `m_cost` which is the most important parameter.
/// The higher the `m_cost` the more secure the hash is but the time it takes to compute it increases linearly.
///
/// ## Presets
///
/// There are some presets for the `Argon2` struct that you can use.
///
/// - `Argon2::very_fast()`
/// - `Argon2::fast()`
/// - `Argon2::balanced()`
/// - `Argon2::slow()`
/// - `Argon2::very_slow()`
#[derive(Default, Clone, Debug)]
pub struct Argon2 {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub hash_length: u64,
    /// By default we use the Argon2id
    pub algorithm: Algorithm,
    /// By default we use the version 0x13
    pub version: Version,
}

impl Argon2 {
    /// Create a new Argon2 instance with the given parameters.
    ///
    /// By default it will use the `Argon2id` with a `64 byte` hash length.
    ///
    /// ## Arguments
    ///
    /// - `m_cost` - The memory cost in kibibytes
    /// - `t_cost` - Iteration cost
    /// - `p_cost` - Parallelization
    pub fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }

    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version = version;
        self
    }

    pub fn with_hash_length(mut self, hash_length: u64) -> Self {
        self.hash_length = hash_length;
        self
    }

    /// Hashes the given password
    ///
    /// ## Arguments
    ///
    /// - `password` - The password to hash
    /// - `salt` - The salt to use for hashing
    ///
    ///
    /// ## Returns
    ///
    /// The hash of the password in its raw byte form
    pub fn hash_password(&self, password: &str, mut salt: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut hash_buffer = vec![0u8; self.hash_length as usize];

        let mut context = argon2_context {
            out: hash_buffer.as_mut_ptr(),
            outlen: self.hash_length as u32,
            pwd: password.as_bytes().as_ptr() as *mut u8,
            pwdlen: password.len() as u32,
            salt: salt.as_mut_ptr(),
            saltlen: salt.len() as u32,
            secret: std::ptr::null_mut(),
            secretlen: 0,
            ad: std::ptr::null_mut(),
            adlen: 0,
            t_cost: self.t_cost,
            m_cost: self.m_cost,
            lanes: self.p_cost,
            threads: self.p_cost,
            version: self.version as u32,
            allocate_cbk: None,
            free_cbk: None,
            flags: ARGON2_DEFAULT_FLAGS,
        };

        let code = unsafe { argon2_ctx(&mut context, self.algorithm as u32) };

        #[cfg(feature = "zeroize")]
        salt.zeroize();

        if code != 0 {
            return Err(Error::Argon2(map_argon2_error(code)));
        }

        Ok(hash_buffer)
    }
}

// Argon2 Presets
impl Argon2 {
    pub fn very_fast() -> Self {
        Self {
            m_cost: 128_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }

    pub fn fast() -> Self {
        Self {
            m_cost: 256_000,
            t_cost: 16,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }

    pub fn balanced() -> Self {
        Self {
            m_cost: 1024_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }

    pub fn slow() -> Self {
        Self {
            m_cost: 2048_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }

    pub fn very_slow() -> Self {
        Self {
            m_cost: 3072_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2() {
        let argon2 = Argon2::very_fast();
        let salt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let hash = argon2.hash_password("password", salt).unwrap();
        assert_eq!(hash.len(), 64);
    }
}
