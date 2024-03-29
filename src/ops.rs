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

use crate::consts;

use blake3;
use rand::{thread_rng, Rng};

pub const IPAD: u8 = 0x36;
pub const OPAD: u8 = 0x5c;

pub fn randomness(size: u16) -> Vec<u8> {
    let mut rng = thread_rng();

    (0..size)
        .map(|_| rng.gen_range(0..u8::MAX))
        .collect::<Vec<u8>>()
}

pub fn keyedHash(input: &Vec<u8>, key: &Vec<u8>, outSize: Option<u16>) -> Vec<u8> {
    let keyIpad: Vec<u8> = exclusiveOR(key, IPAD.to_be_bytes().to_vec().as_ref());
    let keyOpad: Vec<u8> = exclusiveOR(key, OPAD.to_be_bytes().to_vec().as_ref());

    let mut Hasher = blake3::Hasher::new();

    let mut Hash = vec![
        0;
        {
            if let Some(size) = outSize {
                size.into()
            } else {
                consts::KEYED_HASH_SIZE.default.into()
            }
        }
    ];

    Hasher.update([keyIpad, input.clone()].concat().as_slice());
    Hasher.finalize_xof().fill(&mut Hash);

    Hasher.reset();

    Hasher.update([keyOpad, Hash.to_vec()].concat().as_slice());
    Hasher.finalize_xof().fill(&mut Hash);

    Hash.to_vec()
}

pub fn exclusiveOR(fixed: &Vec<u8>, modular: &Vec<u8>) -> Vec<u8> {
    let mut encrypted: Vec<u8> = vec![];
    for offset in 0..fixed.len() {
        encrypted.push(fixed[offset] ^ modular[offset % modular.len()])
    }
    encrypted
}
