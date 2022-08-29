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

use argon2;
use blake3;

pub const IPAD: u8 = 0x36;
pub const OPAD: u8 = 0x5c;

pub fn keyDerive(iv: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let Deriver = argon2::Argon2::new(argon2::Algorithm::default(), argon2::Version::default(), {
        let mut Params = argon2::ParamsBuilder::new();
        Params.output_len(key.len()).unwrap();
        Params.params().unwrap()
    });

    let mut Derived: Vec<u8> = vec![0; key.len()];

    Deriver.hash_password_into(&key, &iv, &mut Derived).unwrap();

    Derived.to_vec()
}

pub fn keyedHash(input: &Vec<u8>, key: &Vec<u8>, outLen: u8) -> Vec<u8> {
    let keyIpad: Vec<u8> = xor(key, IPAD.to_be_bytes().to_vec().as_ref());
    let keyOpad: Vec<u8> = xor(key, OPAD.to_be_bytes().to_vec().as_ref());

    let mut Hasher = blake3::Hasher::new();

    let mut Hash = vec![0; outLen.into()];

    Hasher.update([keyIpad, input.clone()].concat().as_slice());
    Hasher.finalize_xof().fill(&mut Hash);

    Hasher.reset();

    Hasher.update([keyOpad, Hash.to_vec()].concat().as_slice());
    Hasher.finalize_xof().fill(&mut Hash);

    Hash.to_vec()
}

pub fn xor(fixed: &Vec<u8>, modular: &Vec<u8>) -> Vec<u8> {
    let mut encrypted: Vec<u8> = vec![];
    for offset in 0..fixed.len() {
        encrypted.push(fixed[offset] ^ modular[offset % modular.len()])
    }
    encrypted
}
