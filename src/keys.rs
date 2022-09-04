// Komatta
// Copyright (C) 2022 Oscar
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::config;
use crate::ops::randomness;

use argon2;
use flexbuffers;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keys {
    salt: Vec<u8>,
    cypher: Vec<u8>,
    signing: Option<Signing::Keys<Option<Vec<u8>>>>,
    #[serde(skip_serializing, skip_deserializing)]
    subKey: Option<Vec<u8>>,
}

impl Keys {
    fn constraint(&self) -> Result<&Self, String> {
        config::CRYPT_KEY_SIZE.check(self.cypher.len() as u16)?;
        if let Some(signing) = self.signing.clone() {
            if let Some(secret) = signing.secret {
                config::SIGNING_KEY_SIZE.secret.check(secret.len() as u16)?;
            }
            if let Some(public) = signing.public {
                config::SIGNING_KEY_SIZE.public.check(public.len() as u16)?;
            }
        }
        Ok(self)
    }

    pub fn signing(&self) -> Result<Signing::Keys<Option<Vec<u8>>>, String> {
        if let Some(signing) = self.signing.clone() {
            Ok(signing)
        } else {
            Err("Cannot return signing keys as they're not generated!".to_string())
        }
    }

    pub fn subKey(&mut self) -> Result<Vec<u8>, String> {
        self.constraint()?;
        if let Some(subKey) = self.subKey.clone() {
            Ok(subKey)
        } else {
            let Deriver =
                argon2::Argon2::new(argon2::Algorithm::default(), argon2::Version::default(), {
                    let mut Params = argon2::ParamsBuilder::new();
                    Params.output_len(self.cypher.len()).unwrap();
                    Params.params().unwrap()
                });

            let mut Derived: Vec<u8> = vec![0; self.cypher.len()];

            Deriver
                .hash_password_into(&self.cypher.clone(), &self.salt.clone(), &mut Derived)
                .unwrap();

            self.subKey = Some(Derived.clone());

            Ok(Derived)
        }
    }

    pub fn public(&self) -> Result<Self, String> {
        if let Some(signing) = self.signing.clone() {
            Ok(Self {
                salt: self.salt.clone(),
                cypher: self.cypher.clone(),
                signing: Some(signing.public()?),
                subKey: None,
            })
        } else {
            Err("The keypair is not generated!".to_string())
        }
    }

    pub fn new(
        saltSize: Option<u16>,
        cryptKeySize: Option<u16>,
        signing: bool,
    ) -> Result<Self, String> {
        let keys = Self {
            salt: randomness({
                if let Some(size) = saltSize {
                    size
                } else {
                    config::SALT_SIZE.default
                }
            }),
            cypher: randomness({
                if let Some(size) = cryptKeySize {
                    size
                } else {
                    config::CRYPT_KEY_SIZE.default
                }
            }),
            signing: {
                if signing {
                    Some(Signing::Keys::new())
                } else {
                    None
                }
            },
            subKey: None,
        };
        keys.constraint()?;
        Ok(keys)
    }
}

pub mod Signing {
    use pqcrypto::{prelude::*, sign::dilithium5};

    #[derive(Debug, Clone, super::Serialize, super::Deserialize)]
    pub struct Keys<T> {
        pub secret: T,
        pub public: T,
    }

    impl Keys<Option<Vec<u8>>> {
        pub fn new() -> Self {
            let keypair = dilithium5::keypair();
            Self {
                secret: Some(keypair.1.as_bytes().to_vec()),
                public: Some(keypair.0.as_bytes().to_vec()),
            }
        }

        pub fn sign(&self, input: Vec<u8>) -> Result<Vec<u8>, String> {
            if let Some(secretBytes) = self.secret.clone() {
                if let Ok(secret) = dilithium5::SecretKey::from_bytes(&secretBytes) {
                    Ok(dilithium5::detached_sign(&input, &secret)
                        .as_bytes()
                        .to_vec())
                } else {
                    Err("Error while trying to reconstruct the secret key!".to_string())
                }
            } else {
                Err("Unable to sign a message without the secret key!".to_string())
            }
        }

        pub fn verify(&self, input: Vec<u8>, signature: Vec<u8>) -> Result<bool, String> {
            if let None = self.secret.clone() {
                if let Some(publicBytes) = self.public.clone() {
                    if let Ok(public) = dilithium5::PublicKey::from_bytes(&publicBytes) {
                        if let Ok(detachedSignature) =
                            dilithium5::DetachedSignature::from_bytes(&signature)
                        {
                            if let Ok(_) = dilithium5::verify_detached_signature(
                                &detachedSignature,
                                &input,
                                &public,
                            ) {
                                Ok(true)
                            } else {
                                Err("Signature is invalid!".to_string())
                            }
                        } else {
                            Err("Error while trying to reconstruct the signature!".to_string())
                        }
                    } else {
                        Err("Error while trying to reconstruct the public key!".to_string())
                    }
                } else {
                    Err("Unable to verify without the public key!".to_string())
                }
            } else {
                Err("Unable to verify a message while the secret key is defined!".to_string())
            }
        }

        pub fn public(&self) -> Result<Self, String> {
            if let Some(_) = self.public {
                let mut signing = self.clone();
                signing.secret = None;
                Ok(signing)
            } else {
                Err("Cannot return public key as it's not generated!".to_string())
            }
        }
    }
}

impl Default for Keys {
    fn default() -> Self {
        Self {
            salt: Default::default(),
            cypher: Default::default(),
            signing: None,
            subKey: None,
        }
    }
}

impl TryInto<Vec<u8>> for Keys {
    type Error = flexbuffers::SerializationError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        flexbuffers::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for Keys {
    type Error = flexbuffers::DeserializationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        flexbuffers::from_slice(&value)
    }
}
