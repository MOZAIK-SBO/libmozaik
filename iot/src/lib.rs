//! IoT library for MOZAIK
//! 
//! Provides [protect] to encrypt and prepare IoT sensor data for the use in the MOZAIK architecture.
//! 
//! ## How to use
//! ```rust
//! use libmozaik_iot::*;
//! // during initialization of the device
//! let nonce = [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff]; // this should be a fresh nonce
//! let key = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10]; // this should be a fresh device key
//! 
//! let mut state = DeviceState::new(nonce, key);
//! 
//! // when data is available
//! const USER_ID: &str = "e7514b7a-9293-4c83-b733-a53e0e449635";
//! let data = [0x01, 0x02, 0x03]; // data as &[u8] of any length
//! match protect(USER_ID, &mut state, ProtectionAlgorithm::AesGcm128, &data) {
//!     Ok(ct) => {
//!         /* send ct */
//!         # ()
//!     },
//!     Err(err) => {
//!         /* handle error */
//!         # ()
//!     },
//! }
//! ```

use std::{error::Error, fmt::Display};

use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, KeyInit};


const NONCE_SIZE_BITS: usize = 96;
const NONCE_SIZE: usize = NONCE_SIZE_BITS/8;
const MAX_NONCE_CNT: i128 = 1 << NONCE_SIZE_BITS;

const AES_KEY_SIZE: usize = 16;
const AES_GCM_128_TAG_SIZE: usize = 16;

/// State that needs to be persisted between invocations of [protect] with the same device key.
#[derive(Clone)]
pub struct DeviceState {
    used_nonces: i128,
    nonce: [u8; NONCE_SIZE],
    key: [u8; AES_KEY_SIZE],
}

impl DeviceState {
    /// Constructs a new [DeviceState] from a starting nonce and a unused (fresh) device key.
    pub fn new(start_nonce: [u8; NONCE_SIZE], fresh_key: [u8; AES_KEY_SIZE]) -> Self {
        Self {
            used_nonces: 0,
            nonce: start_nonce,
            key: fresh_key,
        }
    }

    fn inc_mod_296(mut x: i128) -> i128 {
        x += 1;
        if x < MAX_NONCE_CNT {
            return x;
        }else{
            return 0;
        }
    }

    fn fresh_nonce(&mut self) -> Result<[u8; NONCE_SIZE], ProtectError> {
        let ctr = self.used_nonces.checked_add(1).unwrap_or(MAX_NONCE_CNT+1);
        if ctr <= MAX_NONCE_CNT {
            self.used_nonces += 1;
            let mut tmp = [0u8; 128/8];
            tmp[..NONCE_SIZE].copy_from_slice(&self.nonce);
            let nonce = Self::inc_mod_296(i128::from_le_bytes(tmp));
            tmp = nonce.to_le_bytes();
            self.nonce.copy_from_slice(&tmp[..NONCE_SIZE]);
            Ok(self.nonce.clone())
        }else{
            Err(ProtectError::RekeyRequired)
        }
    }
}

/// Protects the given data by encrypting it. The returned bytes can be sent to the database.
/// 
/// ## Example Usage
/// ```rust
/// use libmozaik_iot::*;
/// // during initialization of the device
/// let nonce = [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff]; // this should be a fresh nonce
/// let key = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10]; // this should be a fresh device key
/// 
/// let mut state = DeviceState::new(nonce, key);
/// 
/// // when data is available
/// const USER_ID: &str = "e7514b7a-9293-4c83-b733-a53e0e449635";
/// let data = [0x01, 0x02, 0x03]; // data as &[u8] of any length
/// match protect(USER_ID, &mut state, ProtectionAlgorithm::AesGcm128, &data) {
///     Ok(ct) => {
///         /* send ct */
///         # ()
///     },
///     Err(err) => {
///         /* handle error */
///         # ()
///     },
/// }
/// ```
pub fn protect(user_id: &str, state: &mut DeviceState, algorithm: ProtectionAlgorithm, data: &[u8]) -> Result<Vec<u8>, ProtectError> {
    match algorithm {
        ProtectionAlgorithm::AesGcm128 => {
            let instance = Aes128Gcm::new(&state.key.into());

            let nonce = state.fresh_nonce()?;
            let user_id = user_id.as_bytes();
            let mut ad = vec![0u8; user_id.len() + NONCE_SIZE];
            ad[..user_id.len()].copy_from_slice(user_id);
            ad[user_id.len()..].copy_from_slice(&nonce);

            let payload = Payload {
                aad: &ad,
                msg: data
            };

            let mut ciphertext = Vec::with_capacity(NONCE_SIZE + data.len() + AES_GCM_128_TAG_SIZE);
            ciphertext.extend_from_slice(&nonce);

            let mut ct = instance.encrypt(&nonce.into(), payload)?;
            ciphertext.append(&mut ct);

            Ok(ciphertext)
        }
    }
}

/// Error type idicating the nature of the error state returned from [protect].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProtectError {
    /// The maximum number of encryptions have been reached (all nonces have been exhausted).
    /// To continue using [protect], a new device key must be deployed and a new instance of [DeviceState]
    /// must be constructed with a fresh nonce and the new key.
    RekeyRequired,
    /// The AES-GCM library returned an error indicating that encryption failed.
    AesGcm128Error(aes_gcm::Error),
}

/// Selector for the underyling encryption algorithm.
/// Currently, only AES-GCM-128 is supported.
#[derive(Clone, Copy)]
pub enum ProtectionAlgorithm {
    /// AES-GCM-128 (see NIST Special Publication 800-38D \[ <https://doi.org/10.6028/NIST.SP.800-38D> \] and RFC5288).
    AesGcm128
}

impl Error for ProtectError {}

impl Display for ProtectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RekeyRequired => write!(f, "RekeyRequired"),
            Self::AesGcm128Error(aes_err) => write!(f, "AesGcm128Error({})", aes_err),
        }
    }
}

impl From<aes_gcm::Error> for ProtectError {
    fn from(value: aes_gcm::Error) -> Self {
        Self::AesGcm128Error(value)
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, KeyInit};

    use crate::{protect, DeviceState, ProtectError, ProtectionAlgorithm, AES_KEY_SIZE, NONCE_SIZE, NONCE_SIZE_BITS};

    #[test]
    fn rekey_err() {
        let mut state = DeviceState {
            used_nonces: (1 << NONCE_SIZE_BITS) - 1,
            nonce: [0u8; NONCE_SIZE],
            key: [0u8; AES_KEY_SIZE],
        };
        
        assert!(state.fresh_nonce().is_ok());
        assert_eq!(state.used_nonces, 1 << NONCE_SIZE_BITS);

        // all nonces are used up
        assert_eq!(state.fresh_nonce(), Err(ProtectError::RekeyRequired));
        // further calls err
        assert_eq!(state.fresh_nonce(), Err(ProtectError::RekeyRequired));
    }

    
    const KEY: [u8; AES_KEY_SIZE] = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10];
    const USER_ID: &str = "e7514b7a-9293-4c83-b733-a53e0e449635";
    const START_NONCE: [u8; NONCE_SIZE] = [0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff];
    
    const SAMPLE: [u64; 5] = [8647268508341723261, 6019297635911966515, 4304443907393469749,2952975836593986181, 3780177929455862034]; 

    #[test]
    fn protect_decrypts_correctly() {
        
        let mut state = DeviceState::new(START_NONCE.clone(), KEY.clone());
        let data_bytes: Vec<_> = SAMPLE.iter().map(|value| value.to_le_bytes()).flatten().collect();

        let ct = protect(USER_ID, &mut state, ProtectionAlgorithm::AesGcm128, &data_bytes).unwrap();

        // expect nonce in the first NONCE_SIZE bytes of the ciphertext
        assert_eq!(&state.nonce, &ct[..NONCE_SIZE]);

        // expect the nonce is incremented
        let inc_start_nonce = [0x13, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(&state.nonce, &inc_start_nonce);

        // decrypt
        let nonce = &ct[..NONCE_SIZE];
        let ct = &ct[NONCE_SIZE..];
        let mut ad = Vec::new();
        ad.extend_from_slice(USER_ID.as_bytes());
        ad.extend_from_slice(nonce);
        let instance = Aes128Gcm::new(&KEY.into());
        let msg = instance.decrypt(nonce.into(), Payload {
            aad: &ad,
            msg: ct,
        }).unwrap();

        assert_eq!(msg, data_bytes);
    }
}
