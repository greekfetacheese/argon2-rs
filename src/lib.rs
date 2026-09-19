pub mod error;
use error::*;

use argon2_sys::{ARGON2_DEFAULT_FLAGS, ARGON2_OUTPUT_TOO_SHORT, argon2_context, argon2_ctx};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub const RECOMMENDED_HASH_LENGTH: u32 = 64;

/// Minimum hash length Argon2 accepts, in bytes (the C library's `ARGON2_MIN_OUTLEN`).
const MIN_HASH_LENGTH: u32 = 4;

/// Argon2 primitive type: variants of the algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Default, Ord)]
#[repr(u32)]
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
/// By default it will use `Argon2id`, version `0x13` and a `64 byte` hash length.
///
/// It is not recommended to change these specific values, they are fine for most use cases.
///
/// Generally speaking you don't want to mess with the `t_cost` and `p_cost` parameters a lot.
///
/// ## About the `m_cost`, `t_cost` and `p_cost` parameters
///
/// ### `m_cost`
///
/// You should mostly adjust the `m_cost` if you really want to increase the security of the hash since this is
/// the major bottleneck for GPUs and ASICs.
///
/// Anything from `1024_000` and beyond is considered very secure, if you are paranoid you should increase it
/// to the max physical RAM of the machine this hash will be computed on.
///
/// ### `t_cost`
/// For most use cases a good value is between `8` and `30`.
///
/// Increasing the `t_cost` will increase the time it takes to compute the hash linearly.
///
/// For example if the hash takes 10 seconds to compute with `t_cost` set to `8` and you increase it to `16` it will take roughly twice the time.
///
/// ### `p_cost`
///
/// The degree of parallelism (number of lanes and threads). It does **not** change the total
/// amount of work — it only decides how many lanes that work is spread over, so it shortens the
/// wall-clock time only when the machine has spare cores to run those lanes on.
///
/// For example if the hash takes 10 seconds to compute with `p_cost` set to `1` and you increase it to `2`
/// it will take roughly half the time, provided a second core is free; on a single-core machine it will not get faster.
///
/// Keep in mind increasing the `p_cost` beyond the machine's physical cores will not increase the speed of the hash computation
/// but in case of a brute-force attack the attacker will be able to use more cores to compute the hash and thus giving him leverage.
/// For that reason `p_cost` is kept at `1`.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Argon2 {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    /// The length of the hash in bytes.
    ///
    /// Must be at least `4` (`ARGON2_MIN_OUTLEN`) the C library accepts anything up to
    /// `u32::MAX` (`ARGON2_MAX_OUTLEN`), so the type itself is the upper bound.
    pub hash_length: u32,
    /// By default we use the Argon2id
    pub algorithm: Algorithm,
    /// By default we use the version 0x13
    pub version: Version,
}

impl Default for Argon2 {
    /// The [`Argon2::very_fast`] preset: `Argon2id`, version `0x13`, a `64 byte` hash length and
    /// a `128_000` KiB (`128 MiB`) memory cost.
    ///
    /// A configuration with every cost set to `0` can never hash anything, so `Default` is a set
    /// of parameters that actually works, kept cheap enough to use without tuning.
    ///
    /// This must stay a struct literal: every preset below (and [`Argon2::new`]) fills its
    /// remaining fields with `..Default::default()`, so delegating to a preset here would
    /// recurse forever.
    fn default() -> Self {
        Self {
            m_cost: 128_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            algorithm: Algorithm::Argon2id,
            version: Version::V0x13,
        }
    }
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

    /// Sets the hash length in bytes.
    ///
    /// Values below `4` (`ARGON2_MIN_OUTLEN`) are rejected by [`Argon2::hash_password`] with
    /// [`Argon2Error::OutputTooShort`].
    pub fn with_hash_length(mut self, hash_length: u32) -> Self {
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
    pub fn hash_password(&self, password: &str, mut salt: Vec<u8>) -> Result<Vec<u8>, Argon2Error> {
        let mut hash_buffer = vec![0u8; self.hash_length as usize];

        // Argon2 rejects any output shorter than `ARGON2_MIN_OUTLEN`, so return that error
        // without crossing the FFI boundary. The `u32` type already keeps the upper bound at
        // `ARGON2_MAX_OUTLEN`, and a rejected (too short) length cannot make this allocation
        // large, so the buffer never precedes validation in a harmful way.
        let code = if self.hash_length < MIN_HASH_LENGTH {
            ARGON2_OUTPUT_TOO_SHORT
        } else {
            let mut context = argon2_context {
                out: hash_buffer.as_mut_ptr(),
                outlen: self.hash_length,
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

            // SAFETY: `context` is fully initialised above and every pointer in it stays valid
            // for the duration of the call: `out` points at `hash_buffer`, which is allocated to
            // exactly `outlen` bytes; `salt` owns `saltlen` initialised bytes; and `pwd`/`pwdlen`
            // borrow the live `password` string. `ARGON2_DEFAULT_FLAGS` does not set a wipe flag,
            // so the C library only reads `pwd` and `salt` and writes at most `outlen` bytes
            // through `out`.
            unsafe { argon2_ctx(&mut context, self.algorithm as u32) }
        };

        #[cfg(feature = "zeroize")]
        salt.zeroize();

        if code != 0 {
            return Err(map_argon2_error(code));
        }

        Ok(hash_buffer)
    }

    /// Encodes the Argon2 configuration into a byte vector using little-endian byte order.
    ///
    /// `hash_length` is written as an 8-byte field, so the encoded form is still 28 bytes long.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(28);
        let version = self.version as u32;
        buf.extend_from_slice(&self.m_cost.to_le_bytes());
        buf.extend_from_slice(&self.t_cost.to_le_bytes());
        buf.extend_from_slice(&self.p_cost.to_le_bytes());
        buf.extend_from_slice(&(self.hash_length as u64).to_le_bytes());
        buf.extend_from_slice(&(self.algorithm as u32).to_le_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        buf
    }

    /// Decodes the Argon2 configuration from a byte slice using little-endian byte order.
    ///
    /// # Errors
    ///
    /// Returns `Error::Argon2(Argon2Error::DecodingFail)` if the data is too short, contains
    /// invalid enum values, or holds a `hash_length` that does not fit in a `u32`.
    pub fn decode(data: &[u8]) -> Result<Self, Argon2Error> {
        if data.len() < 28 {
            return Err(Argon2Error::DecodingFail);
        }

        let m_cost = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let t_cost = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let p_cost = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let hash_length_u64 = u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);
        let alg_u32 = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let version_u32 = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let hash_length = u32::try_from(hash_length_u64).map_err(|_| Argon2Error::DecodingFail)?;

        let algorithm = match alg_u32 {
            0 => Algorithm::Argon2d,
            1 => Algorithm::Argon2i,
            2 => Algorithm::Argon2id,
            _ => return Err(Argon2Error::DecodingFail),
        };

        let version = match version_u32 {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            _ => return Err(Argon2Error::DecodingFail),
        };

        Ok(Self {
            m_cost,
            t_cost,
            p_cost,
            hash_length,
            algorithm,
            version,
        })
    }
}

// Argon2 Presets
impl Argon2 {
    /// The [`Default`] configuration.
    pub fn very_fast() -> Self {
        Self::default()
    }

    pub fn fast() -> Self {
        Self {
            m_cost: 256_000,
            t_cost: 16,
            hash_length: RECOMMENDED_HASH_LENGTH,
            p_cost: 1,
            ..Default::default()
        }
    }

    pub fn balanced() -> Self {
        Self {
            m_cost: 1_024_000,
            t_cost: 8,
            hash_length: RECOMMENDED_HASH_LENGTH,
            p_cost: 1,
            ..Default::default()
        }
    }

    pub fn slow() -> Self {
        Self {
            m_cost: 2_048_000,
            t_cost: 8,
            hash_length: RECOMMENDED_HASH_LENGTH,
            p_cost: 1,
            ..Default::default()
        }
    }

    pub fn very_slow() -> Self {
        Self {
            m_cost: 3_072_000,
            t_cost: 8,
            hash_length: RECOMMENDED_HASH_LENGTH,
            p_cost: 1,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    #[test]
    fn test_argon2() -> Result<(), Argon2Error> {
        let argon2 = Argon2::very_fast();
        let hash = argon2.hash_password("password", SALT.to_vec())?;
        assert_eq!(hash.len(), 64);

        Ok(())
    }

    #[test]
    fn test_encode_decode() -> Result<(), Argon2Error> {
        let argon2 = Argon2::balanced();
        let encoded = argon2.encode();
        assert_eq!(encoded.len(), 28);
        let decoded = Argon2::decode(&encoded)?;
        assert_eq!(argon2, decoded);

        Ok(())
    }

    #[test]
    fn test_default_is_a_usable_configuration() {
        // `Default` used to leave every cost at zero, which can never hash anything.
        let expected = Argon2 {
            m_cost: 128_000,
            t_cost: 8,
            p_cost: 1,
            hash_length: RECOMMENDED_HASH_LENGTH,
            algorithm: Algorithm::Argon2id,
            version: Version::V0x13,
        };
        assert_eq!(Argon2::default(), expected);
    }

    #[test]
    fn test_presets_do_not_recurse() {
        // Regression guard: `Default` must stay a struct literal. If it delegates to a preset
        // that fills its fields from `..Default::default()`, every preset recurses forever.
        for preset in [
            Argon2::very_fast(),
            Argon2::fast(),
            Argon2::balanced(),
            Argon2::slow(),
            Argon2::very_slow(),
            Argon2::new(64, 3, 1),
        ] {
            assert_eq!(preset.algorithm, Algorithm::Argon2id);
            assert_eq!(preset.version, Version::V0x13);
            assert_eq!(preset.hash_length, RECOMMENDED_HASH_LENGTH);
        }
    }

    #[test]
    fn test_hash_length_bounds() {
        // Every length below `ARGON2_MIN_OUTLEN` is rejected before entering the C library.
        for bad in 0..MIN_HASH_LENGTH {
            let result = Argon2::new(64, 3, 1)
                .with_hash_length(bad)
                .hash_password("password", SALT.to_vec());
            assert_eq!(result, Err(Argon2Error::OutputTooShort));
        }

        // The minimum valid length hashes and yields exactly that many bytes.
        let hash = Argon2::new(64, 3, 1)
            .with_hash_length(MIN_HASH_LENGTH)
            .hash_password("password", SALT.to_vec())
            .expect("minimum hash length must hash");
        assert_eq!(hash.len(), MIN_HASH_LENGTH as usize);
    }

    #[test]
    fn test_encode_decode_keeps_the_28_byte_wire_format() {
        let argon2 = Argon2::default().with_hash_length(96);
        let encoded = argon2.encode();
        assert_eq!(encoded.len(), 28);
        assert_eq!(Argon2::decode(&encoded), Ok(argon2));
    }

    #[test]
    fn test_decode_rejects_hash_length_above_u32() {
        let mut encoded = Argon2::balanced().encode();
        encoded[12..20].copy_from_slice(&0x1_0000_0000u64.to_le_bytes());
        assert_eq!(Argon2::decode(&encoded), Err(Argon2Error::DecodingFail));
    }
}
