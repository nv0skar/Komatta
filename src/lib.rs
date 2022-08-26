// Komatta
// Copyright (C) 2022 Oscar
//
// This program is fre&e software: you can redistribute it and/or modify
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
pub mod ops;

use actions::Action;
use ops::{keyDerive, keyedHash, xor};

use argon2;
use rand::{thread_rng, Rng};

pub const BLOCK_SIZE: usize = 64;
pub const ROUNDS: usize = 32;

#[derive(Debug)]
pub struct Cypher {
    pub action: actions::Action,
    pub key: Vec<u8>,
    pub input: Vec<u8>,
}

impl Cypher {
    pub fn process(&self) -> Result<Vec<u8>, &str> {
        assert!(BLOCK_SIZE <= argon2::MAX_SALT_LEN);
        assert!(BLOCK_SIZE >= argon2::MIN_SALT_LEN && BLOCK_SIZE >= 4);
        assert!(self.key.len() <= argon2::MAX_PWD_LEN);
        match self.action {
            Action::Encrypt => {
                let mut rng = thread_rng();
                let iv: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen_range(0..u8::MAX)).collect();

                let devKey = keyDerive(&iv, &self.key);

                let decrypted = self.input.chunks(BLOCK_SIZE);
                let mut encrypted: Vec<Vec<u8>> = vec![];

                for (offset, block) in decrypted.enumerate() {
                    let lastBlockProcessed = {
                        if let Some(lastBlock) = encrypted.last() {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&iv, &devKey)
                        }
                    };
                    let lastBlockHash = keyedHash(&lastBlockProcessed, &devKey);
                    let mut counter: Vec<u8> = keyedHash(&offset.to_be_bytes().to_vec(), &devKey);
                    for time in 0..ROUNDS {
                        let mut rotatedKey = devKey.clone();
                        rotatedKey.rotate_right(time % &devKey.len());
                        counter = xor(&counter, &rotatedKey);
                    }
                    counter = xor(&counter, &lastBlockHash);
                    encrypted.push(xor(&xor(&block.to_vec(), &counter), &lastBlockHash));
                }

                Ok([
                    iv,
                    encrypted.concat(),
                    keyedHash(&encrypted.concat(), &devKey),
                ]
                .concat())
            }
            Action::Decrypt => {
                let iv: Vec<u8> = self.input.get(0..BLOCK_SIZE).unwrap().to_vec();

                let devKey = keyDerive(&iv, &self.key);

                let encrypted = self
                    .input
                    .get(BLOCK_SIZE..(self.input.len() - BLOCK_SIZE))
                    .unwrap()
                    .to_vec();
                let tag = self
                    .input
                    .get((self.input.len() - BLOCK_SIZE)..self.input.len())
                    .unwrap()
                    .to_vec();

                if keyedHash(&encrypted, &devKey) != tag {
                    return Err("Bad data integrity!");
                }

                let mut lastEncryptedBlock: Option<Vec<u8>> = None;
                let mut decrypted: Vec<Vec<u8>> = vec![];

                for (offset, block) in encrypted.chunks(BLOCK_SIZE).enumerate() {
                    let lastEncryptedBlockProcessed = {
                        if let Some(lastBlock) = lastEncryptedBlock {
                            lastBlock.to_vec()
                        } else {
                            keyedHash(&iv, &devKey)
                        }
                    };
                    lastEncryptedBlock = Some(block.to_vec());

                    let lastBlockHash = keyedHash(&lastEncryptedBlockProcessed, &devKey);
                    let mut counter: Vec<u8> = keyedHash(&offset.to_be_bytes().to_vec(), &devKey);
                    for time in 0..ROUNDS {
                        let mut rotatedKey = devKey.clone();
                        rotatedKey.rotate_right(ROUNDS - (time % &devKey.len()) - 1);
                        counter = xor(&counter, &rotatedKey);
                    }
                    counter = xor(&counter, &lastBlockHash);
                    decrypted.push(xor(&xor(&block.to_vec(), &counter), &lastBlockHash));
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

        let mut crypto = crate::Cypher {
            action: crate::Action::Encrypt,
            key,
            input: input.clone(),
        };

        let encrypted = crypto.process().unwrap();

        crypto.action = crate::Action::Decrypt;
        crypto.input = encrypted;

        let decrypted = crypto.process().unwrap();

        assert_eq!(input, decrypted);
    }
}
