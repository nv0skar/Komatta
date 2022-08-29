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

pub mod actions;
pub mod defaults;
pub mod ops;
pub mod parameters;

use actions::Action;
use ops::{keyDerive, keyedHash, xor};
use parameters::Parameters;

use argon2;
use rand::{thread_rng, Rng};

#[derive(Debug)]
pub struct Cypher {
    pub action: actions::Action,
    pub key: Vec<u8>,
    pub input: Vec<u8>,
    pub parameters: Option<Parameters>,
}

impl Cypher {
    pub fn process(&self) -> Result<Vec<u8>, &str> {
        assert!(defaults::MIN_KEY_SIZE <= self.key.len() && argon2::MAX_PWD_LEN >= self.key.len());
        match self.action {
            Action::Encrypt => {
                let parameters = self.parameters.unwrap_or(Parameters::default());
                parameters.check();

                let mut rng = thread_rng();
                let iv: Vec<u8> = (0..parameters.iv_size)
                    .map(|_| rng.gen_range(0..u8::MAX))
                    .collect();

                let devKey = keyDerive(&iv, &self.key);

                let decrypted = self.input.chunks(parameters.block_size.into());
                let mut encrypted: Vec<Vec<u8>> = vec![];

                for (offset, block) in decrypted.enumerate() {
                    let lastEncryptedBlock = {
                        if let Some(lastBlock) = encrypted.last() {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&iv, &devKey, parameters.keyed_hash_size)
                        }
                    };

                    let mut counter: Vec<u8> = keyedHash(
                        &offset.to_be_bytes().to_vec(),
                        &devKey,
                        parameters.keyed_hash_size,
                    );
                    counter = xor(&counter, &lastEncryptedBlock);

                    encrypted.push(xor(&block.to_vec(), &counter));
                }

                Ok([
                    parameters.into(),
                    iv,
                    encrypted.concat(),
                    keyedHash(&encrypted.concat(), &devKey, parameters.tag_size),
                ]
                .concat())
            }
            Action::Decrypt => {
                let parameters = {
                    let size = Parameters::paramsLen();
                    (
                        size,
                        Parameters::from(self.input.get(0..size).unwrap().to_vec()),
                    )
                };
                parameters.1.check();

                let iv: Vec<u8> = self
                    .input
                    .get(parameters.0..(parameters.1.iv_size as usize + parameters.0))
                    .unwrap()
                    .to_vec();

                let encrypted = self
                    .input
                    .get(
                        (parameters.1.iv_size as usize + parameters.0)
                            ..(self.input.len() - parameters.1.tag_size as usize),
                    )
                    .unwrap()
                    .to_vec();
                let tag = self
                    .input
                    .get((self.input.len() - parameters.1.tag_size as usize)..self.input.len())
                    .unwrap()
                    .to_vec();

                let devKey = keyDerive(&iv, &self.key);

                if keyedHash(&encrypted, &devKey, parameters.1.tag_size) != tag {
                    return Err("Bad data integrity!");
                }

                let mut lastEncryptedBlock: Option<Vec<u8>> = None;
                let mut decrypted: Vec<Vec<u8>> = vec![];

                for (offset, block) in encrypted.chunks(parameters.1.block_size.into()).enumerate()
                {
                    let lastEncryptedBlockProcessed = {
                        if let Some(lastBlock) = lastEncryptedBlock {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&iv, &devKey, parameters.1.keyed_hash_size)
                        }
                    };
                    lastEncryptedBlock = Some(block.to_vec());

                    let mut counter: Vec<u8> = keyedHash(
                        &offset.to_be_bytes().to_vec(),
                        &devKey,
                        parameters.1.keyed_hash_size,
                    );
                    counter = xor(&counter, &lastEncryptedBlockProcessed);

                    decrypted.push(xor(&block.to_vec(), &counter));
                }

                Ok(decrypted.concat())
            }
        }
    }
}

#[cfg(test)]
mod Tests {
    use rand::{thread_rng, Rng};

    #[test]
    fn cypher() {
        let mut rng = thread_rng();

        let input: Vec<u8> = (0..128).map(|_| rng.gen_range(0..u8::MAX)).collect();
        let key: Vec<u8> = (0..64).map(|_| rng.gen_range(0..u8::MAX)).collect();

        let mut crypt = crate::Cypher {
            action: crate::Action::Encrypt,
            key,
            input: input.clone(),
            parameters: None,
        };

        crypt.input = crypt.process().unwrap();
        crypt.action = crate::Action::Decrypt;

        let decrypted = crypt.process().unwrap();

        assert_eq!(input, decrypted);
    }
}
