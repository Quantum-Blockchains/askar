//! ML-DSA-44 signature and verification key support

use super::{HasKeyAlg, HasKeyBackend, KeyAlg};
use crate::{
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    generic_array::typenum::{Sum, U1000, U312, U32},
    // jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};
use core::fmt::{self, Debug, Formatter};

use pqcrypto::traits::sign::{PublicKey, SecretKey};
use pqcrypto::{sign::mldsa44, traits::sign::DetachedSignature};

// use crystals_dilithium::ml_dsa_44::{Keypair, PublicKey, SecretKey, KEYPAIRBYTES, PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};

const MLDSA44_SECRET_LENGTH: usize = 32;
const MLDSA44_SIGNATURE_LENGTH: usize = mldsa44::signature_bytes();
const MLDSA44_PUBLIC_KEY_LENGTH: usize = mldsa44::public_key_bytes();
const MLDSA44_SECRET_KEY_LENGTH: usize = mldsa44::secret_key_bytes();
const MLDSA44_KEYPAIR_LENGTH: usize = MLDSA44_SECRET_LENGTH + MLDSA44_PUBLIC_KEY_LENGTH;

type U1312 = Sum<U1000, U312>;
type U1344 = Sum<U1312, U32>;

/// An ML-DSA-44 public key or keypair
#[derive(Clone)]
pub struct MLDSA44KeyPair {
    secret: Option<[u8; MLDSA44_SECRET_LENGTH]>,
    public: [u8; MLDSA44_PUBLIC_KEY_LENGTH],
}

impl MLDSA44KeyPair {
    #[inline]
    pub(crate) fn from_secret_key(secret: &[u8; MLDSA44_SECRET_LENGTH]) -> Self {
        let (pk, _) = mldsa44::keypair_from_seed(secret);
        Self {
            secret: Some(*secret),
            public: pk.as_bytes().try_into().unwrap(),
        }
    }

    // pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {

    // }

    /// Create a signing key from the secret key
    pub fn to_signing_key(&self) -> Option<MLDSA44SigningKey> {
        self.secret.as_ref().map(|sk| {
            MLDSA44SigningKey(
                mldsa44::keypair_from_seed(sk)
                    .1
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            )
        })
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<[u8; MLDSA44_SIGNATURE_LENGTH]> {
        self.to_signing_key().map(|sk| sk.sign(message))
    }

    /// Verify a signature against the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = mldsa44::DetachedSignature::from_bytes(signature) {
            let vk = mldsa44::PublicKey::from_bytes(&self.public).unwrap();
            mldsa44::verify_detached_signature(&sig, message, &vk).is_ok()
        } else {
            false
        }
    }
}

impl Debug for MLDSA44KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MLDSA44KeyPair")
            .field(
                "secret",
                if self.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.public)
            .finish()
    }
}

impl KeyGen for MLDSA44KeyPair {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        let sk = ArrayKey::<U32>::generate(rng);
        Ok(Self::from_secret_key((&sk).try_into().unwrap()))
    }
}

impl HasKeyBackend for MLDSA44KeyPair {}

impl HasKeyAlg for MLDSA44KeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::MLDSA44
    }
}

impl KeyMeta for MLDSA44KeyPair {
    type KeySize = U1312;
}

impl KeySecretBytes for MLDSA44KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        let sk: &[u8; MLDSA44_SECRET_LENGTH] =
            key.try_into().map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self::from_secret_key(sk))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(self.secret.as_ref().map(|sk| &sk[..]))
    }
}

impl KeypairMeta for MLDSA44KeyPair {
    type PublicKeySize = U1312;
    type KeypairSize = U1344;
}

impl KeypairBytes for MLDSA44KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != MLDSA44_KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        // NB: this is infallible if the slice is the right length
        let result = MLDSA44KeyPair::from_secret_bytes(&kp[..MLDSA44_SECRET_LENGTH])?;
        // TODO
        //result.check_public_bytes(&kp[SECRETKEYBYTES..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(secret) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                arr[..MLDSA44_SECRET_LENGTH].copy_from_slice(secret);
                arr[MLDSA44_SECRET_LENGTH..].copy_from_slice(&self.public[..]);
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for MLDSA44KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let vk = key
            .try_into()
            .ok()
            .and_then(|k| mldsa44::PublicKey::from_bytes(k).ok())
            .ok_or_else(|| err_msg!(InvalidKeyData))?;
        Ok(Self {
            secret: None,
            public: vk.as_bytes().try_into().unwrap(),
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(&self.public[..])
    }
}

impl KeySign for MLDSA44KeyPair {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        match sig_type {
            None | Some(SignatureType::MLDSA44) => {
                if let Some(signer) = self.to_signing_key() {
                    let sig = signer.sign(message);
                    out.buffer_write(&sig[..])?;
                    Ok(())
                } else {
                    Err(err_msg!(MissingSecretKey))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeySigVerify for MLDSA44KeyPair {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::MLDSA44) => Ok(self.verify_signature(message, signature)),
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

// impl Drop for MLDSA44KeyPair {
//     fn drop(&mut self) {
//         self.secret.zeroize();
//         self.public.zeroize();
//     }
// }

// impl ZeroizeOnDrop for Ed25519KeyPair {}

/// A ML-DSA-44 secret key used for signing
#[derive(Debug, Clone)]
pub struct MLDSA44SigningKey([u8; MLDSA44_SECRET_KEY_LENGTH]);

impl MLDSA44SigningKey {
    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> [u8; MLDSA44_SIGNATURE_LENGTH] {
        let sk = mldsa44::SecretKey::from_bytes(&self.0).unwrap();
        mldsa44::detached_sign(message, &sk)
            .as_bytes()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;
    use crate::repr::{ToPublicBytes, ToSecretBytes};

    #[test]
    fn expand_keypair() {
        let seed = b"000000000000000000000000Trustee1";
        let test_sk = &hex!("3030303030303030303030303030303030303030303030305472757374656531af221edaa593fa1c944d1314f09d1a57c365d0b3fe6326193905a3a7f6e380ef66d27bb69c06950eaf79b5a392d7e7e776f92c51218b2dbe31f6571a65ee5e60e64ea64311bbd90f502543e1616f4927af7aaa1173db940165eb43d7f7024c95439db39d03a7d708c34d209df3148d5d7df923541eca13b3a94fe907182c7192c41ebea3f9c8c2b9fba09e287bbeafa0053c3cf544954ec7a2557da044bb65791b774c0c70b1a3e15f391b338f5fff9a64eaf101bd2006254a71cedbaca30b21db2864b8d9af71ec0c3278003cc4f239087a420ca1200e28eae752bf4c9773c92f03af8de0cbf18838312a29607af68b44cf8c578fc085463c1eb4f1c51149356f677389a75ab99045daf7f230578546233faa36e9e83fcaa4d9404e5f91e7616bb92dc71c750f65808868f6654837d317248ba4d2949fc40cafe004ff3c3b67230d430b49fa4c688a9a2a2f10576fef7f487bf6071647fe8b2c0d508c27d953504572f56c84283223a46d449884aaadff4e52cd67d5bf83e455ed458eeb5a131207cff52e7833baa22baced538c67a5c0447c7885110919244b09a5baa4af64389ec2eb57b7858a7d2146a8481b6c7d32f4a83cafe5b75b17df7f06625f11fdca40307de5220e63fb2190c21d88221fbf46a133ecc8bc654ce1af7afc38cbafe2a5495b27b42a297a4c04bb041ddf0b1bf5760734e747f1d8b797c99d013c71ab1c26aa09df221671dd1e059e01c17381f8ddf2522c3342ee61895ffb5b70b17007cf982aa672eb6d1f658c582bc176676655c00e7f5d8f68e89434c24028e0af0f09cf2af8d2cdd2ce23958c65ea5028a492ad30c98efaddbf2d416d83aa248aa1dcd17254b7a484f563a5fdef7ae47919c266060d4997f069bf1a5c301484137faa3eca5beb5b1465e2a7ace3348c14f6e156c0a52cff05e0db680ded2564b2e4afa810377292b4707256727aeffadfc13d8cf2a97bb64871a3501210c8393a0fdee605e5d3132ab15349610154ca066188a5890cbbd907f42b5b122d720491da18477852ccb7b741ca6f4e378c017276f72c4b268e87ae5d1a464f7ca9a859991a5fdac94f20769c21dcb708318812dab05c298112a40a82518d54fcb36c872e0c604b2485570e685d7dc1a01a93043303bd2c8ba96e864c10b0ab0c02230c9384e5e6075f5a34260daa1d754173ecb8b4b8e2c50c23e384c86c9a817e46baf5c5e1ea26c995a7dc30a8593783ecd4c367303630647ae08399d00fb9cb3f7d2e794eef21d21d7ed55305048b1b694ebe1ee68e3bdbd251f613484d35609e8600ea6a439b7068e1e99e0477d3bf8f7e7954091071f5bc4385ced5635213804fbe04cec95556b65d925f7e1f055362060d4b029b4324885de0a30e516e4a54b46c700f6dbc1b9e4dc4cbc44f155ca09f72b458eb6d35d96934221d6b382171cb05982cc4ab4854d045d8d342a541ceee06a7a5d6960fc8e424062e755019bc3fa4781703d724d45743aac19e1e8207cc6e304d2695f46614d65cf747c2d644752f24df928eee00bf25fd50c26dc471d81c06d470dad4cfdef9d0212d6354d3fba5735ac4cfa6e3b6555ebf0553bf83e74e4162c3cd895a20bd30018b4e06dbbc93fae2db8cda2c87f34a3f601c1fe13b7a197632bd3765a09a17afe4a7ea07393737ceec66bf08ae934addeb1090d61b09c304cee11273c69cb6ccd8c63e23870a2cc4ddb1071dfa4874379575e56a9442b538ab1d4c57ed1ab20b8e7ae29d35f51a83ef0739e9034a0cb7939a9fdc9d54122bab0134e9a202333718a28e8b04d423496f27b20407c57db6387f4a3ba22de3dc08f1abac2f7cd67e7416bb4f");

        let kp = MLDSA44KeyPair::from_secret_bytes(seed).unwrap();
        assert_eq!(kp.to_keypair_bytes().unwrap(), &test_sk[..]);
        assert_eq!(kp.to_secret_bytes().unwrap(), &seed[..]);

        // test round trip
        let cmp = MLDSA44KeyPair::from_keypair_bytes(test_sk).unwrap();
        assert_eq!(cmp.to_keypair_bytes().unwrap(), &test_sk[..]);
    }

    // #[test]
    // fn ed25519_to_x25519() {
    //     let test_keypair = &hex!("1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf");
    //     let x_sk = &hex!("08e7286c232ec71b37918533ea0229bf0c75d3db4731df1c5c03c45bc909475f");
    //     let x_pk = &hex!("9b4260484c889158c128796103dc8d8b883977f2ef7efb0facb12b6ca9b2ae3d");
    //     let x_pair = Ed25519KeyPair::from_keypair_bytes(test_keypair)
    //         .unwrap()
    //         .to_x25519_keypair()
    //         .to_keypair_bytes()
    //         .unwrap();
    //     assert_eq!(&x_pair[..32], x_sk);
    //     assert_eq!(&x_pair[32..], x_pk);
    // }

    // #[test]
    // fn jwk_expected() {
    //     // from https://www.connect2id.com/blog/nimbus-jose-jwt-6
    //     // {
    //     //     "kty" : "OKP",
    //     //     "crv" : "Ed25519",
    //     //     "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    //     //     "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
    //     //     "use" : "sig",
    //     //     "kid" : "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
    //     //   }
    //     let test_pvt_b64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    //     let test_pub_b64 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    //     let test_pvt = base64::engine::general_purpose::URL_SAFE_NO_PAD
    //         .decode(test_pvt_b64)
    //         .unwrap();
    //     let kp = Ed25519KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");
    //     let jwk = kp
    //         .to_jwk_public(None)
    //         .expect("Error converting public key to JWK");
    //     let jwk = JwkParts::try_from_str(&jwk).expect("Error parsing JWK output");
    //     assert_eq!(jwk.kty, JWK_KEY_TYPE);
    //     assert_eq!(jwk.crv, JWK_CURVE);
    //     assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
    //     let pk_load = Ed25519KeyPair::from_jwk_parts(jwk).unwrap();
    //     assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

    //     let jwk = kp
    //         .to_jwk_secret(None)
    //         .expect("Error converting private key to JWK");
    //     let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK output");
    //     assert_eq!(jwk.kty, JWK_KEY_TYPE);
    //     assert_eq!(jwk.crv, JWK_CURVE);
    //     assert_eq!(jwk.x, test_pub_b64);
    //     assert_eq!(jwk.d, test_pvt_b64);
    //     let sk_load = Ed25519KeyPair::from_jwk_parts(jwk).unwrap();
    //     assert_eq!(
    //         kp.to_keypair_bytes().unwrap(),
    //         sk_load.to_keypair_bytes().unwrap()
    //     );
    // }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        // let test_sig: [u8; 2420] = [175, 148, 84, 44, 134, 234, 250, 183, 108, 213, 147, 73, 189, 144, 70, 15, 12, 252, 135, 52, 47, 255, 186, 87, 24, 78, 1, 25, 92, 227, 147, 210, 226, 51, 94, 54, 131, 134, 208, 238, 119, 9, 130, 165, 182, 40, 150, 173, 37, 0, 191, 173, 167, 124, 117, 19, 69, 137, 185, 0, 212, 141, 163, 11, 244, 68, 99, 184, 15, 43, 94, 150, 235, 79, 67, 141, 231, 11, 139, 139, 123, 243, 62, 140, 71, 169, 39, 101, 209, 42, 46, 49, 0, 182, 18, 206, 27, 103, 16, 62, 240, 234, 161, 58, 97, 165, 253, 225, 112, 117, 208, 240, 14, 163, 176, 123, 13, 144, 191, 126, 219, 193, 121, 150, 214, 193, 207, 218, 54, 108, 209, 251, 20, 230, 244, 233, 120, 121, 120, 137, 111, 213, 110, 113, 174, 239, 12, 247, 80, 196, 162, 225, 130, 216, 197, 241, 203, 255, 120, 132, 100, 148, 75, 158, 240, 221, 71, 141, 100, 252, 173, 173, 5, 136, 114, 83, 251, 153, 131, 239, 24, 45, 206, 43, 228, 204, 45, 232, 254, 109, 112, 8, 21, 188, 212, 2, 231, 144, 44, 233, 197, 182, 188, 237, 232, 37, 147, 157, 26, 185, 123, 225, 199, 143, 248, 88, 221, 42, 14, 242, 120, 141, 23, 9, 255, 210, 146, 149, 159, 205, 211, 113, 159, 105, 193, 220, 205, 215, 70, 195, 167, 41, 219, 213, 1, 2, 20, 193, 183, 215, 220, 45, 72, 166, 171, 197, 207, 13, 59, 2, 62, 223, 50, 200, 19, 88, 242, 241, 252, 247, 62, 181, 69, 145, 20, 165, 246, 35, 166, 88, 76, 70, 76, 184, 14, 142, 153, 184, 13, 10, 182, 224, 13, 113, 224, 60, 116, 59, 166, 27, 245, 29, 155, 43, 32, 197, 91, 50, 220, 234, 218, 239, 193, 102, 240, 39, 217, 110, 237, 100, 95, 203, 191, 153, 85, 199, 95, 122, 133, 254, 139, 37, 90, 241, 34, 137, 3, 164, 239, 6, 65, 46, 172, 189, 124, 48, 173, 108, 206, 11, 95, 45, 190, 27, 132, 58, 186, 35, 31, 193, 244, 225, 154, 198, 63, 208, 13, 141, 82, 129, 229, 61, 64, 222, 34, 12, 16, 157, 99, 235, 151, 103, 134, 147, 217, 90, 238, 199, 152, 201, 177, 157, 193, 46, 212, 215, 93, 39, 84, 37, 4, 142, 185, 146, 217, 147, 226, 46, 80, 97, 168, 39, 96, 160, 212, 254, 36, 177, 74, 137, 213, 75, 54, 33, 101, 115, 168, 197, 65, 181, 84, 203, 159, 187, 81, 224, 131, 219, 55, 34, 64, 45, 247, 151, 221, 2, 173, 68, 102, 59, 18, 97, 49, 91, 34, 22, 208, 253, 144, 58, 178, 161, 23, 179, 61, 126, 96, 190, 194, 142, 185, 234, 20, 237, 147, 219, 19, 9, 14, 90, 166, 95, 206, 241, 66, 251, 129, 107, 89, 74, 79, 251, 111, 95, 35, 169, 95, 50, 11, 172, 74, 154, 227, 200, 57, 162, 100, 237, 235, 245, 235, 126, 194, 105, 28, 250, 57, 210, 136, 215, 62, 24, 31, 217, 151, 172, 26, 235, 12, 206, 108, 49, 170, 62, 107, 223, 137, 172, 250, 157, 95, 66, 169, 158, 166, 19, 90, 89, 214, 234, 73, 196, 179, 5, 19, 195, 138, 184, 9, 189, 22, 142, 6, 42, 206, 68, 134, 34, 49, 41, 28, 228, 24, 135, 170, 158, 12, 9, 90, 248, 105, 248, 167, 20, 252, 160, 129, 10, 82, 87, 249, 27, 37, 5, 103, 28, 176, 40, 134, 182, 2, 195, 65, 222, 186, 179, 115, 1, 35, 24, 250, 234, 57, 125, 137, 61, 51, 60, 61, 143, 25, 185, 105, 26, 189, 112, 148, 210, 86, 63, 247, 104, 50, 141, 64, 122, 182, 77, 160, 223, 182, 12, 191, 80, 246, 212, 111, 95, 200, 58, 21, 11, 213, 84, 127, 94, 191, 30, 227, 188, 105, 170, 157, 227, 151, 212, 249, 242, 242, 204, 240, 49, 223, 211, 57, 115, 205, 21, 216, 96, 79, 116, 206, 230, 19, 47, 199, 141, 79, 108, 193, 132, 191, 220, 114, 76, 21, 157, 84, 35, 252, 171, 195, 65, 159, 251, 197, 135, 118, 222, 160, 37, 48, 4, 189, 52, 87, 62, 75, 101, 79, 193, 173, 5, 129, 41, 86, 209, 246, 231, 134, 137, 22, 224, 68, 63, 121, 59, 153, 80, 232, 94, 213, 108, 59, 25, 35, 130, 49, 228, 252, 9, 4, 233, 223, 190, 75, 158, 90, 184, 177, 130, 73, 77, 192, 94, 198, 190, 30, 246, 16, 94, 129, 196, 79, 202, 177, 190, 4, 68, 2, 200, 123, 73, 229, 112, 58, 207, 83, 136, 183, 205, 157, 88, 91, 154, 28, 126, 24, 102, 98, 192, 64, 139, 37, 255, 121, 4, 22, 43, 113, 130, 218, 79, 107, 133, 173, 133, 84, 19, 75, 148, 123, 160, 155, 105, 147, 90, 58, 204, 220, 119, 126, 183, 77, 117, 12, 69, 177, 113, 246, 65, 223, 198, 87, 64, 164, 184, 73, 74, 84, 222, 200, 229, 247, 96, 134, 159, 120, 18, 221, 80, 240, 52, 226, 56, 32, 211, 215, 23, 211, 250, 23, 45, 87, 170, 186, 40, 248, 62, 104, 116, 215, 161, 64, 51, 98, 24, 133, 10, 206, 208, 69, 115, 213, 139, 134, 90, 160, 100, 80, 158, 96, 238, 224, 15, 14, 203, 79, 91, 110, 239, 96, 34, 146, 150, 140, 92, 51, 166, 20, 188, 255, 63, 233, 101, 108, 173, 117, 52, 231, 30, 27, 47, 181, 92, 18, 189, 49, 159, 75, 255, 2, 104, 86, 190, 16, 100, 206, 40, 75, 234, 156, 236, 10, 74, 53, 0, 190, 253, 55, 202, 39, 134, 102, 96, 48, 168, 179, 37, 63, 205, 143, 166, 33, 205, 163, 113, 32, 18, 50, 95, 30, 195, 231, 147, 149, 162, 116, 198, 144, 96, 18, 79, 222, 52, 130, 11, 97, 74, 123, 89, 231, 201, 115, 42, 147, 50, 55, 161, 118, 233, 147, 240, 67, 153, 80, 142, 51, 36, 53, 61, 104, 78, 225, 172, 26, 82, 94, 162, 83, 192, 142, 79, 134, 22, 166, 165, 100, 209, 145, 183, 25, 201, 65, 22, 42, 78, 210, 193, 77, 13, 40, 57, 83, 99, 16, 99, 224, 69, 170, 246, 105, 112, 117, 121, 100, 225, 136, 112, 29, 151, 90, 115, 149, 103, 172, 81, 29, 4, 129, 166, 80, 24, 0, 184, 64, 247, 205, 107, 237, 147, 140, 42, 124, 143, 173, 83, 243, 199, 64, 125, 65, 216, 58, 131, 245, 65, 45, 45, 68, 214, 75, 216, 207, 206, 31, 181, 125, 51, 79, 163, 41, 161, 1, 205, 200, 155, 198, 181, 167, 117, 156, 15, 202, 178, 91, 136, 78, 157, 4, 44, 227, 214, 74, 79, 141, 158, 152, 19, 72, 118, 87, 79, 206, 58, 235, 155, 36, 255, 1, 78, 56, 132, 107, 139, 153, 104, 48, 29, 194, 214, 34, 153, 207, 228, 22, 126, 161, 69, 175, 104, 144, 50, 124, 166, 129, 135, 50, 162, 225, 12, 227, 11, 86, 105, 60, 227, 156, 184, 250, 157, 28, 163, 180, 189, 40, 248, 11, 166, 96, 112, 244, 240, 240, 201, 208, 177, 150, 218, 214, 59, 174, 228, 44, 84, 122, 190, 188, 137, 201, 192, 113, 162, 121, 208, 74, 112, 90, 180, 139, 222, 217, 35, 199, 145, 14, 225, 146, 219, 136, 239, 239, 211, 70, 136, 111, 109, 128, 27, 142, 11, 127, 18, 137, 117, 12, 191, 192, 145, 242, 129, 54, 19, 214, 51, 208, 203, 210, 131, 254, 36, 119, 151, 71, 23, 96, 93, 127, 1, 197, 89, 94, 23, 7, 118, 234, 191, 208, 1, 69, 228, 146, 159, 24, 94, 52, 158, 75, 29, 187, 141, 13, 108, 146, 192, 128, 72, 213, 16, 181, 41, 171, 227, 210, 126, 244, 253, 20, 248, 147, 9, 44, 243, 97, 60, 6, 199, 179, 125, 24, 184, 64, 44, 64, 43, 24, 68, 189, 144, 130, 220, 46, 180, 250, 90, 14, 82, 48, 197, 207, 101, 212, 69, 37, 14, 10, 230, 172, 8, 10, 61, 226, 77, 159, 245, 185, 61, 238, 92, 221, 21, 90, 195, 112, 88, 46, 93, 243, 89, 232, 251, 98, 154, 190, 75, 235, 98, 230, 154, 236, 70, 62, 27, 234, 108, 252, 190, 218, 244, 18, 23, 0, 20, 62, 86, 172, 81, 99, 6, 9, 237, 84, 204, 214, 79, 89, 101, 1, 1, 8, 130, 28, 30, 97, 87, 50, 53, 11, 3, 229, 240, 53, 175, 134, 56, 50, 32, 72, 202, 128, 156, 76, 233, 236, 122, 167, 140, 172, 212, 49, 168, 251, 113, 198, 147, 159, 46, 217, 72, 41, 152, 185, 159, 40, 252, 52, 246, 11, 181, 194, 203, 16, 248, 86, 230, 161, 171, 235, 119, 102, 180, 80, 34, 91, 179, 101, 133, 80, 134, 144, 91, 35, 132, 77, 80, 16, 155, 153, 159, 52, 184, 90, 66, 4, 208, 71, 206, 82, 83, 52, 26, 160, 163, 249, 130, 46, 228, 134, 223, 124, 191, 254, 24, 8, 183, 209, 3, 199, 79, 236, 150, 111, 39, 128, 225, 215, 160, 58, 89, 66, 162, 56, 44, 112, 112, 30, 23, 12, 217, 42, 248, 234, 196, 144, 187, 121, 55, 147, 102, 111, 181, 160, 115, 106, 18, 199, 205, 99, 177, 106, 183, 248, 77, 135, 192, 246, 58, 158, 218, 100, 22, 148, 104, 47, 135, 240, 49, 40, 73, 72, 64, 198, 84, 56, 192, 47, 129, 196, 22, 167, 133, 59, 203, 52, 226, 255, 214, 200, 108, 136, 184, 212, 40, 196, 80, 19, 183, 156, 124, 182, 120, 148, 106, 173, 16, 143, 156, 44, 81, 91, 111, 242, 73, 144, 91, 152, 62, 147, 234, 130, 17, 156, 162, 86, 92, 168, 174, 192, 93, 45, 226, 132, 55, 28, 100, 52, 178, 118, 115, 10, 74, 40, 19, 195, 170, 5, 219, 54, 122, 145, 15, 134, 39, 120, 28, 179, 199, 218, 127, 11, 82, 132, 178, 75, 66, 252, 196, 20, 229, 53, 200, 201, 44, 103, 40, 247, 88, 247, 192, 73, 7, 84, 11, 21, 238, 130, 116, 215, 224, 200, 121, 120, 26, 186, 160, 67, 78, 188, 248, 173, 231, 188, 87, 217, 165, 231, 39, 43, 151, 198, 230, 179, 150, 122, 44, 81, 146, 48, 125, 67, 73, 26, 138, 204, 127, 199, 16, 104, 112, 251, 204, 185, 145, 100, 233, 58, 183, 102, 163, 162, 218, 116, 224, 125, 223, 238, 92, 190, 252, 114, 61, 157, 253, 14, 161, 204, 142, 99, 49, 243, 145, 173, 136, 219, 6, 252, 184, 112, 219, 202, 91, 95, 144, 144, 96, 100, 163, 163, 67, 163, 179, 65, 84, 172, 175, 115, 254, 38, 159, 114, 219, 137, 71, 144, 9, 35, 86, 96, 37, 234, 143, 63, 180, 74, 29, 155, 33, 5, 222, 24, 218, 184, 224, 43, 142, 96, 224, 42, 92, 164, 147, 164, 210, 158, 239, 11, 230, 122, 95, 75, 66, 233, 30, 38, 81, 44, 117, 0, 69, 117, 133, 19, 251, 200, 251, 77, 108, 14, 81, 68, 140, 149, 167, 160, 166, 233, 84, 217, 18, 214, 147, 46, 14, 103, 40, 170, 149, 173, 46, 152, 94, 212, 159, 237, 54, 196, 59, 0, 222, 95, 184, 26, 84, 128, 43, 91, 253, 83, 130, 161, 56, 23, 208, 150, 159, 226, 249, 23, 184, 127, 110, 154, 39, 49, 83, 224, 211, 89, 197, 68, 47, 138, 232, 192, 8, 237, 126, 153, 4, 136, 98, 191, 236, 214, 138, 2, 185, 86, 115, 56, 146, 35, 186, 172, 92, 107, 220, 110, 62, 68, 198, 81, 63, 235, 128, 4, 55, 129, 197, 215, 88, 51, 129, 174, 194, 7, 117, 195, 17, 35, 187, 199, 30, 135, 237, 189, 152, 81, 197, 76, 222, 210, 139, 69, 50, 61, 134, 100, 3, 240, 159, 196, 238, 111, 47, 161, 226, 191, 169, 25, 192, 72, 253, 100, 22, 249, 18, 173, 138, 79, 155, 24, 164, 150, 229, 42, 92, 79, 214, 92, 242, 133, 120, 63, 0, 74, 64, 40, 86, 129, 249, 91, 240, 235, 245, 12, 209, 161, 170, 218, 236, 66, 220, 30, 43, 168, 8, 253, 25, 148, 81, 66, 121, 235, 159, 138, 246, 2, 205, 71, 17, 50, 209, 124, 66, 26, 252, 91, 52, 149, 151, 103, 76, 197, 89, 111, 244, 186, 83, 148, 183, 6, 168, 54, 136, 207, 84, 201, 253, 205, 175, 132, 232, 231, 132, 33, 99, 93, 222, 255, 75, 40, 207, 47, 216, 16, 192, 110, 189, 133, 126, 7, 21, 88, 92, 6, 91, 173, 233, 184, 202, 45, 131, 217, 124, 155, 1, 209, 59, 72, 106, 156, 241, 136, 111, 74, 171, 92, 171, 252, 200, 75, 121, 249, 78, 209, 241, 45, 202, 219, 228, 242, 212, 255, 223, 187, 158, 18, 19, 191, 6, 65, 240, 70, 32, 51, 9, 50, 63, 151, 152, 68, 151, 125, 14, 27, 253, 238, 125, 240, 242, 108, 216, 230, 145, 110, 48, 232, 94, 129, 101, 78, 3, 220, 32, 136, 143, 188, 173, 54, 97, 193, 36, 97, 245, 238, 232, 3, 205, 210, 40, 53, 47, 219, 96, 243, 214, 202, 156, 208, 108, 20, 30, 204, 57, 62, 139, 157, 60, 105, 204, 133, 195, 146, 10, 67, 251, 26, 195, 166, 123, 17, 142, 163, 231, 203, 195, 217, 197, 202, 17, 179, 16, 234, 102, 185, 12, 40, 1, 155, 159, 153, 32, 47, 188, 4, 38, 178, 132, 163, 96, 100, 231, 214, 127, 58, 20, 117, 174, 235, 100, 238, 254, 166, 188, 79, 78, 204, 7, 222, 196, 113, 146, 66, 221, 156, 248, 228, 79, 199, 134, 32, 60, 87, 237, 46, 137, 9, 119, 194, 19, 128, 105, 32, 233, 21, 23, 32, 66, 70, 94, 110, 111, 116, 118, 123, 142, 147, 154, 163, 197, 223, 229, 238, 239, 34, 37, 80, 81, 137, 144, 168, 179, 198, 214, 218, 254, 1, 22, 36, 52, 57, 64, 65, 90, 117, 129, 145, 155, 165, 199, 220, 221, 225, 236, 245, 254, 16, 28, 46, 62, 72, 95, 102, 122, 149, 169, 171, 177, 236, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 32, 52, 66];

        let test_keypair = &hex!(
            "3030303030303030303030303030303030303030303030305472757374656531
            af221edaa593fa1c944d1314f09d1a57c365d0b3fe6326193905a3a7f6e380ef6
            6d27bb69c06950eaf79b5a392d7e7e776f92c51218b2dbe31f6571a65ee5e60e6
            4ea64311bbd90f502543e1616f4927af7aaa1173db940165eb43d7f7024c95439
            db39d03a7d708c34d209df3148d5d7df923541eca13b3a94fe907182c7192c41e
            bea3f9c8c2b9fba09e287bbeafa0053c3cf544954ec7a2557da044bb65791b774
            c0c70b1a3e15f391b338f5fff9a64eaf101bd2006254a71cedbaca30b21db2864
            b8d9af71ec0c3278003cc4f239087a420ca1200e28eae752bf4c9773c92f03af8
            de0cbf18838312a29607af68b44cf8c578fc085463c1eb4f1c51149356f677389
            a75ab99045daf7f230578546233faa36e9e83fcaa4d9404e5f91e7616bb92dc71
            c750f65808868f6654837d317248ba4d2949fc40cafe004ff3c3b67230d430b49
            fa4c688a9a2a2f10576fef7f487bf6071647fe8b2c0d508c27d953504572f56c8
            4283223a46d449884aaadff4e52cd67d5bf83e455ed458eeb5a131207cff52e78
            33baa22baced538c67a5c0447c7885110919244b09a5baa4af64389ec2eb57b78
            58a7d2146a8481b6c7d32f4a83cafe5b75b17df7f06625f11fdca40307de5220e
            63fb2190c21d88221fbf46a133ecc8bc654ce1af7afc38cbafe2a5495b27b42a2
            97a4c04bb041ddf0b1bf5760734e747f1d8b797c99d013c71ab1c26aa09df2216
            71dd1e059e01c17381f8ddf2522c3342ee61895ffb5b70b17007cf982aa672eb6
            d1f658c582bc176676655c00e7f5d8f68e89434c24028e0af0f09cf2af8d2cdd2
            ce23958c65ea5028a492ad30c98efaddbf2d416d83aa248aa1dcd17254b7a484f
            563a5fdef7ae47919c266060d4997f069bf1a5c301484137faa3eca5beb5b1465
            e2a7ace3348c14f6e156c0a52cff05e0db680ded2564b2e4afa810377292b4707
            256727aeffadfc13d8cf2a97bb64871a3501210c8393a0fdee605e5d3132ab153
            49610154ca066188a5890cbbd907f42b5b122d720491da18477852ccb7b741ca6
            f4e378c017276f72c4b268e87ae5d1a464f7ca9a859991a5fdac94f20769c21dc
            b708318812dab05c298112a40a82518d54fcb36c872e0c604b2485570e685d7dc
            1a01a93043303bd2c8ba96e864c10b0ab0c02230c9384e5e6075f5a34260daa1d
            754173ecb8b4b8e2c50c23e384c86c9a817e46baf5c5e1ea26c995a7dc30a8593
            783ecd4c367303630647ae08399d00fb9cb3f7d2e794eef21d21d7ed55305048b
            1b694ebe1ee68e3bdbd251f613484d35609e8600ea6a439b7068e1e99e0477d3b
            f8f7e7954091071f5bc4385ced5635213804fbe04cec95556b65d925f7e1f0553
            62060d4b029b4324885de0a30e516e4a54b46c700f6dbc1b9e4dc4cbc44f155ca
            09f72b458eb6d35d96934221d6b382171cb05982cc4ab4854d045d8d342a541ce
            ee06a7a5d6960fc8e424062e755019bc3fa4781703d724d45743aac19e1e8207c
            c6e304d2695f46614d65cf747c2d644752f24df928eee00bf25fd50c26dc471d8
            1c06d470dad4cfdef9d0212d6354d3fba5735ac4cfa6e3b6555ebf0553bf83e74
            e4162c3cd895a20bd30018b4e06dbbc93fae2db8cda2c87f34a3f601c1fe13b7a
            197632bd3765a09a17afe4a7ea07393737ceec66bf08ae934addeb1090d61b09c
            304cee11273c69cb6ccd8c63e23870a2cc4ddb1071dfa4874379575e56a9442b5
            38ab1d4c57ed1ab20b8e7ae29d35f51a83ef0739e9034a0cb7939a9fdc9d54122
            bab0134e9a202333718a28e8b04d423496f27b20407c57db6387f4a3ba22de3dc
            08f1abac2f7cd67e7416bb4f"
        );
        let kp = MLDSA44KeyPair::from_keypair_bytes(test_keypair).unwrap();
        let sig = &kp.sign(test_msg).unwrap();
        // assert_eq!(sig, &test_sig);
        assert!(kp.verify_signature(test_msg, &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(test_msg, &[0u8; 64]));
    }

    // #[test]
    // fn round_trip_bytes() {
    //     let kp = Ed25519KeyPair::random().unwrap();
    //     let cmp = Ed25519KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
    //     assert_eq!(
    //         kp.to_keypair_bytes().unwrap(),
    //         cmp.to_keypair_bytes().unwrap()
    //     );
    // }
}
