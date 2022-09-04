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

#![allow(non_snake_case)]

pub mod config;
pub mod keys;
pub mod ops;
pub mod target;

use crate::keys::Keys;
use crate::ops::{exclusiveOR, keyedHash, randomness};
use crate::target::Target;

use flexbuffers;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypt {
    #[serde(skip_serializing, skip_deserializing)]
    pub target: Target,
    #[serde(skip_serializing, skip_deserializing)]
    pub keys: Keys,
    block_size: u16,
    iv: Vec<u8>,
    pub input: Vec<u8>,
    pub integrity: Integrity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Integrity {
    Signed(Option<Vec<u8>>),
    Unsigned(Option<Vec<u8>>),
}

impl Into<u8> for Integrity {
    fn into(self) -> u8 {
        match self {
            Integrity::Signed(_) => 0,
            Integrity::Unsigned(_) => 1,
        }
    }
}

impl From<u8> for Integrity {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Self::Signed(None),
            1 => Self::Unsigned(None),
            _ => panic!(
                "'{}' is not a valid representation of an integrity type!",
                byte
            ),
        }
    }
}

impl Crypt {
    pub fn process(&mut self) -> Result<Vec<u8>, String> {
        match self.target {
            Target::Encrypt => {
                let cyphered = self.cypher()?;
                {
                    let construction = self.construct(cyphered.clone());
                    match self.integrity {
                        Integrity::Signed(_) => {
                            self.integrity =
                                Integrity::Signed(Some(self.keys.signing()?.sign(construction)?));
                        }
                        Integrity::Unsigned(_) => {
                            self.integrity = Integrity::Unsigned(Some(keyedHash(
                                &construction,
                                &self.keys.subKey()?,
                                None,
                            )));
                        }
                    }
                }
                Ok(cyphered)
            }

            Target::Decrypt => {
                let construction = self.construct(self.input.clone());
                if let Integrity::Signed(Some(integrity)) = self.integrity.clone() {
                    if self.keys.signing()?.verify(construction, integrity)? {
                        Ok(self.cypher()?)
                    } else {
                        Err("Invalid signature!".to_string())
                    }
                } else if let Integrity::Unsigned(Some(integrity)) = self.integrity.clone() {
                    if integrity == keyedHash(&construction, &self.keys.subKey()?, None) {
                        Ok(self.cypher()?)
                    } else {
                        Err("Invalid hash!".to_string())
                    }
                } else {
                    Err("Cannot verify integrity as it's not defined!".to_string())
                }
            }
        }
    }

    fn construct(&self, cyphered: Vec<u8>) -> Vec<u8> {
        [
            self.block_size.to_be_bytes().to_vec(),
            [Into::<u8>::into(self.integrity.clone())].to_vec(),
            self.iv.clone(),
            cyphered,
        ]
        .concat()
    }

    fn cypher(&mut self) -> Result<Vec<u8>, String> {
        match self.target {
            Target::Encrypt => {
                let plaintext = self.input.chunks(self.block_size.into());
                let mut ciphertext: Vec<Vec<u8>> = vec![];
                for (offset, block) in plaintext.enumerate() {
                    let lastEncryptedBlock = {
                        if let Some(lastBlock) = ciphertext.last() {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&self.iv, &self.keys.subKey()?, None)
                        }
                    };

                    let mut counter: Vec<u8> =
                        keyedHash(&offset.to_be_bytes().to_vec(), &self.keys.subKey()?, None);
                    counter = exclusiveOR(&counter, &lastEncryptedBlock);

                    ciphertext.push(exclusiveOR(&block.to_vec(), &counter));
                }
                Ok(ciphertext.concat())
            }
            Target::Decrypt => {
                let mut lastEncryptedBlock: Option<Vec<u8>> = None;
                let mut plaintext: Vec<Vec<u8>> = vec![];
                for (offset, block) in self.input.chunks(self.block_size.into()).enumerate() {
                    let lastEncryptedBlockProcessed = {
                        if let Some(lastBlock) = lastEncryptedBlock {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&self.iv, &self.keys.subKey()?, None)
                        }
                    };
                    lastEncryptedBlock = Some(block.to_vec());

                    let mut counter: Vec<u8> =
                        keyedHash(&offset.to_be_bytes().to_vec(), &self.keys.subKey()?, None);
                    counter = exclusiveOR(&counter, &lastEncryptedBlockProcessed);

                    plaintext.push(exclusiveOR(&block.to_vec(), &counter));
                }
                Ok(plaintext.concat())
            }
        }
    }

    pub fn import(
        target: Target,
        keys: Keys,
        iv: Vec<u8>,
        block_size: Option<u16>,
        input: Vec<u8>,
        integrity: Integrity,
    ) -> Self {
        Self {
            target,
            keys: keys,
            block_size: {
                if let Some(size) = block_size {
                    size
                } else {
                    config::BLOCK_SIZE.default
                }
            },
            iv,
            input,
            integrity,
        }
    }

    pub fn new(
        target: Target,
        keys: Keys,
        iv_size: Option<u16>,
        block_size: Option<u16>,
        input: Vec<u8>,
        integrity: Integrity,
    ) -> Self {
        Self {
            target,
            keys: keys,
            block_size: {
                if let Some(size) = block_size {
                    size
                } else {
                    config::BLOCK_SIZE.default
                }
            },
            iv: {
                randomness({
                    if let Some(size) = iv_size {
                        size
                    } else {
                        config::IV_SIZE.default
                    }
                })
            },
            input,
            integrity,
        }
    }
}

impl TryInto<Vec<u8>> for Crypt {
    type Error = flexbuffers::SerializationError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        flexbuffers::to_vec(&self)
    }
}

impl TryFrom<Vec<u8>> for Crypt {
    type Error = flexbuffers::DeserializationError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        flexbuffers::from_slice(&value)
    }
}
