//! X25519 key exchange support on Curve25519

use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

use subtle::ConstantTimeEq;
// use x25519_dalek::{PublicKey, StaticSecret as SecretKey};
use zeroize::Zeroizing;

use super::{ed25519::Ed25519KeyPair, HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    generic_array::typenum::{U64, U800, U864},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchange,
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
};

use pqcrypto::kem::mlkem512;
use pqcrypto::traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};

// FIXME: reject low-order points?
// <https://github.com/tendermint/tmkms/pull/279>
// vs. <https://cr.yp.to/ecdh.html> which indicates that all points are safe for normal D-H.

/// The length of a public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = mlkem512::public_key_bytes();
/// The length of a secret key in bytes
pub const SECRET_KEY_LENGTH: usize = 64;
/// The length of a keypair in bytes
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The 'kty' value of an ML-KEM-512 JWK
pub const JWK_KEY_TYPE: &str = "LATTICE";
/// The 'crv' value of an ML-KEM-512 JWK
pub const JWK_CURVE: &str = "ML-KEM-512";

type Secret = [u8; SECRET_KEY_LENGTH];

/// An X25519 public key or keypair
#[derive(Clone)]
pub struct MLKEM512KeyPair {
    // SECURITY: SecretKey (StaticSecret) zeroizes on drop
    pub(crate) secret: Option<Secret>,
    pub(crate) public: mlkem512::PublicKey,
}

impl MLKEM512KeyPair {
    #[inline(always)]
    pub(crate) fn new(sk: Option<Secret>, pk: mlkem512::PublicKey) -> Self {
        Self {
            secret: sk,
            public: pk,
        }
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: Secret) -> Self {
        let (public, _) = mlkem512::keypair_from_seed(sk);
        // let public = PublicKey::from(&sk);
        Self {
            secret: Some(sk),
            public,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.public.as_bytes().ct_eq(pk).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid ML-KEM-512 keypair"))
        }
    }

    /// encapsulate
    pub fn encapsulate(&self) -> ([u8; 32], [u8; 768]) {
        let (shared_secret, cipher_text) = mlkem512::encapsulate(&self.public);
        let mut ss = [0u8; 32];
        ss.copy_from_slice(shared_secret.as_bytes());
        let mut ct = [0u8; 768];
        ct.copy_from_slice(cipher_text.as_bytes());
        return (ss, ct)
    }

    /// decapsulate
    pub fn decapsulate(&self, ct: &[u8]) -> [u8; 32] {
        let (_, sk) = mlkem512::keypair_from_seed(self.secret.unwrap());
        let ct = mlkem512::Ciphertext::from_bytes(ct).unwrap();
        let shared_secret = mlkem512::decapsulate(&ct, &sk);
        let mut ss = [0u8; 32];
        ss.copy_from_slice(shared_secret.as_bytes());
        ss
    }
}

impl Debug for MLKEM512KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MLKEM512KeyPair")
            .field(
                "secret",
                if self.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.public.as_bytes())
            .finish()
    }
}

impl HasKeyBackend for MLKEM512KeyPair {}

impl HasKeyAlg for MLKEM512KeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::MLKEM512
    }
}

impl KeyMeta for MLKEM512KeyPair {
    type KeySize = U800;
}

impl KeyGen for MLKEM512KeyPair {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        let sk = ArrayKey::<U64>::generate(rng);
        let sk = Secret::from(*<&[u8; SECRET_KEY_LENGTH]>::try_from(&sk).unwrap());
        let (pk, _) = mlkem512::keypair_from_seed(sk);
        // let pk = PublicKey::from(&sk);
        Ok(Self::new(Some(sk), pk))
    }
}

impl KeySecretBytes for MLKEM512KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        let sk: &[u8; SECRET_KEY_LENGTH] = key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::from_secret_key(Secret::from(*sk)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let b = Zeroizing::new(*sk);
            f(Some(&b[..]))
        } else {
            f(None)
        }
    }
}

impl KeypairMeta for MLKEM512KeyPair {
    type PublicKeySize = U800;
    type KeypairSize = U864;
}

impl KeypairBytes for MLKEM512KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        let result = Self::from_secret_bytes(&kp[..SECRET_KEY_LENGTH])?;
        result.check_public_bytes(&kp[SECRET_KEY_LENGTH..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(secret) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                arr[..SECRET_KEY_LENGTH].copy_from_slice(secret);
                arr[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for MLKEM512KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk: &[u8; PUBLIC_KEY_LENGTH] = key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::new(None, PublicKey::from_bytes(pk).unwrap()))
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(&self.public.as_bytes()[..])
    }
}

impl ToJwk for MLKEM512KeyPair {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        self.with_public_bytes(|buf| enc.add_as_base64("x", buf))?;
        if enc.is_secret() {
            self.with_secret_bytes(|buf| {
                if let Some(sk) = buf {
                    enc.add_as_base64("d", sk)
                } else {
                    Ok(())
                }
            })?;
        }
        Ok(())
    }
}

impl FromJwk for MLKEM512KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        ArrayKey::<U800>::temp(|pk_arr| {
            if jwk.x.decode_base64(pk_arr)? != pk_arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else if jwk.d.is_some() {
                ArrayKey::<U64>::temp(|sk_arr| {
                    if jwk.d.decode_base64(sk_arr)? != sk_arr.len() {
                        Err(err_msg!(InvalidKeyData))
                    } else {
                        let kp = MLKEM512KeyPair::from_secret_bytes(sk_arr)?;
                        kp.check_public_bytes(pk_arr)?;
                        Ok(kp)
                    }
                })
            } else {
                MLKEM512KeyPair::from_public_bytes(pk_arr)
            }
        })
    }
}

// impl KeyExchange for MLKEM512KeyPair {
//     fn write_key_exchange(&self, other: &Self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
//         match self.secret.as_ref() {
//             Some(sk) => {
//                 let xk = sk.diffie_hellman(&other.public);
//                 out.buffer_write(xk.as_bytes())?;
//                 Ok(())
//             }
//             None => Err(err_msg!(MissingSecretKey)),
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::repr::ToPublicBytes;

    #[test]
    pub fn test_kem() {
        let k = MLKEM512KeyPair::random().unwrap();
        let (ss1, ct) = k.encapsulate();
        let ss2 = k.decapsulate(&ct);
        assert_eq!(&ss1[..], &ss2[..], "Difference in shared secrets!");
    }

    #[test]
    fn jwk_expected() {
        // {
        //   "kty": "LATTICE",
        //   "d": "SFwKjw6PYteO0xiTeC_5FKPxaVZS3Mhsjns2JmiBLALbT8UHKzE1JuAbFVlK6jMzB_0e4QwACGMk32fD5k7uvw",
        //   "use": "enc",
        //   "crv": "ML-KEM-512",
        //   "x": "JohOSWmQgoyp9iRS76EKTPdEsrNNXJcjfyYuOmw7keUtdbaNPnvBDMA9z0KpkJNFIgF1Muix3HMPmKIwicMlCIsedKHEjfUqVTQFQ6qrR2x2ohFNl5aZY4LAJDG9x-QHRlGjc9d6fcUYftw7OOgUY6K9nFJLqIFhAKxHF2MS5huw-ltKqAgQLAGUDgBowLGwCmxOTkvFBUxEN_uWb9iwbvNhX3MQ2VhuvqE8m1VROoMyDrgErFXOFqqlvTBfKumx0XVgSqJaTTOV21oXR-BMxmZ2JCWCieypedNP7mACtFkbeioZaJOI2sBVFCR1wmBtLGOYP3uNbQEr95iqqDiAuEKd9raDyZBC4uaxUyKP4uPNHUmneTcTpAiQKtF9PkR7M-Vl4YRRG7qqOyVAfDNOYpY54cCxMnR02UUQyeSb9cVTdnx96Kk310IHn4wEw7xnzyI8C4KzAzaTXPLCoXIv5ie-mYWf_VCHBdTGKmGkTwU3zWS0VROAz_eCl-A2ASmfS6MxN9Qz6XN8dUElFvFZdopQBSOZlyGmU-U1FnCblfQpiNLJP5xN3BNaiWGI1bs1WaaFnsNrKOxxsIRCZYmk_RDPlQKAt6ggKJYNlYd8STRqezaxpEgmpJRpFjSeigGw4fyRmkah0KnN4PSHWCrP8KUQnWlkEXVV62Y-ZEh8bGVYccV--SljIwd9g-yYj0GF4nktjlqRhvwJe5Esimp6NOUEORlexdd8UlfBXkBKKdYzBjAqiOEkgyNlgIPM5GdD_iYTEhU2RhW2H7cJg5Jl-PXCbTFQaWMZztgqKIlOTUS9L4Wv5AE6nBJQLNNCoZS5HngOVCQs7ZqBk8NmScS_vbSf7Cd92eV-feoQXScs7mkg8dRWcreDZzwdYEppF-Z5lLISwYil5QiIZyWr7Pc9wYRa-QZci4EBw9wsxKFLExh_WwAZMyInp8Elz0SE4cGc0xgInLqa95vKSpLMjFcrbiabLvg1c6WqpDKpy9U7IPt2r2dbgzQwiGbEe1S-nlSvo9P1-CMygOU73dLOUzqKK-DfxcArBL4hWJ-jL9rE7PA"
        // }
        let test_pvt_b64 = "SFwKjw6PYteO0xiTeC_5FKPxaVZS3Mhsjns2JmiBLALbT8UHKzE1JuAbFVlK6jMzB_0e4QwACGMk32fD5k7uvw";
        let test_pvt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(test_pvt_b64)
            .unwrap();
        let kp =
            MLKEM512KeyPair::from_secret_bytes(&test_pvt).expect("Error creating x25519 keypair");
        let jwk = kp
            .to_jwk_public(None)
            .expect("Error converting public key to JWK");
        let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "JohOSWmQgoyp9iRS76EKTPdEsrNNXJcjfyYuOmw7keUtdbaNPnvBDMA9z0KpkJNFIgF1Muix3HMPmKIwicMlCIsedKHEjfUqVTQFQ6qrR2x2ohFNl5aZY4LAJDG9x-QHRlGjc9d6fcUYftw7OOgUY6K9nFJLqIFhAKxHF2MS5huw-ltKqAgQLAGUDgBowLGwCmxOTkvFBUxEN_uWb9iwbvNhX3MQ2VhuvqE8m1VROoMyDrgErFXOFqqlvTBfKumx0XVgSqJaTTOV21oXR-BMxmZ2JCWCieypedNP7mACtFkbeioZaJOI2sBVFCR1wmBtLGOYP3uNbQEr95iqqDiAuEKd9raDyZBC4uaxUyKP4uPNHUmneTcTpAiQKtF9PkR7M-Vl4YRRG7qqOyVAfDNOYpY54cCxMnR02UUQyeSb9cVTdnx96Kk310IHn4wEw7xnzyI8C4KzAzaTXPLCoXIv5ie-mYWf_VCHBdTGKmGkTwU3zWS0VROAz_eCl-A2ASmfS6MxN9Qz6XN8dUElFvFZdopQBSOZlyGmU-U1FnCblfQpiNLJP5xN3BNaiWGI1bs1WaaFnsNrKOxxsIRCZYmk_RDPlQKAt6ggKJYNlYd8STRqezaxpEgmpJRpFjSeigGw4fyRmkah0KnN4PSHWCrP8KUQnWlkEXVV62Y-ZEh8bGVYccV--SljIwd9g-yYj0GF4nktjlqRhvwJe5Esimp6NOUEORlexdd8UlfBXkBKKdYzBjAqiOEkgyNlgIPM5GdD_iYTEhU2RhW2H7cJg5Jl-PXCbTFQaWMZztgqKIlOTUS9L4Wv5AE6nBJQLNNCoZS5HngOVCQs7ZqBk8NmScS_vbSf7Cd92eV-feoQXScs7mkg8dRWcreDZzwdYEppF-Z5lLISwYil5QiIZyWr7Pc9wYRa-QZci4EBw9wsxKFLExh_WwAZMyInp8Elz0SE4cGc0xgInLqa95vKSpLMjFcrbiabLvg1c6WqpDKpy9U7IPt2r2dbgzQwiGbEe1S-nlSvo9P1-CMygOU73dLOUzqKK-DfxcArBL4hWJ-jL9rE7PA");
        assert_eq!(jwk.d, None);
        let pk_load = MLKEM512KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp
            .to_jwk_secret(None)
            .expect("Error converting private key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "JohOSWmQgoyp9iRS76EKTPdEsrNNXJcjfyYuOmw7keUtdbaNPnvBDMA9z0KpkJNFIgF1Muix3HMPmKIwicMlCIsedKHEjfUqVTQFQ6qrR2x2ohFNl5aZY4LAJDG9x-QHRlGjc9d6fcUYftw7OOgUY6K9nFJLqIFhAKxHF2MS5huw-ltKqAgQLAGUDgBowLGwCmxOTkvFBUxEN_uWb9iwbvNhX3MQ2VhuvqE8m1VROoMyDrgErFXOFqqlvTBfKumx0XVgSqJaTTOV21oXR-BMxmZ2JCWCieypedNP7mACtFkbeioZaJOI2sBVFCR1wmBtLGOYP3uNbQEr95iqqDiAuEKd9raDyZBC4uaxUyKP4uPNHUmneTcTpAiQKtF9PkR7M-Vl4YRRG7qqOyVAfDNOYpY54cCxMnR02UUQyeSb9cVTdnx96Kk310IHn4wEw7xnzyI8C4KzAzaTXPLCoXIv5ie-mYWf_VCHBdTGKmGkTwU3zWS0VROAz_eCl-A2ASmfS6MxN9Qz6XN8dUElFvFZdopQBSOZlyGmU-U1FnCblfQpiNLJP5xN3BNaiWGI1bs1WaaFnsNrKOxxsIRCZYmk_RDPlQKAt6ggKJYNlYd8STRqezaxpEgmpJRpFjSeigGw4fyRmkah0KnN4PSHWCrP8KUQnWlkEXVV62Y-ZEh8bGVYccV--SljIwd9g-yYj0GF4nktjlqRhvwJe5Esimp6NOUEORlexdd8UlfBXkBKKdYzBjAqiOEkgyNlgIPM5GdD_iYTEhU2RhW2H7cJg5Jl-PXCbTFQaWMZztgqKIlOTUS9L4Wv5AE6nBJQLNNCoZS5HngOVCQs7ZqBk8NmScS_vbSf7Cd92eV-feoQXScs7mkg8dRWcreDZzwdYEppF-Z5lLISwYil5QiIZyWr7Pc9wYRa-QZci4EBw9wsxKFLExh_WwAZMyInp8Elz0SE4cGc0xgInLqa95vKSpLMjFcrbiabLvg1c6WqpDKpy9U7IPt2r2dbgzQwiGbEe1S-nlSvo9P1-CMygOU73dLOUzqKK-DfxcArBL4hWJ-jL9rE7PA");
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = MLKEM512KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
    }

}
