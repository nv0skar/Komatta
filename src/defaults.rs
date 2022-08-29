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

use std::ops::Range;

use argon2;
use blake3;

pub const BLOCK_SIZE: u8 = 64;
pub const KEYED_HASH_SIZE: u8 = 32;
pub const IV_SIZE: u8 = 8;
pub const TAG_SIZE: u8 = 16;

pub const BLOCK_SIZE_RANGE: Range<u8> = 4..u8::MAX;
pub const KEYED_HASH_SIZE_RANGE: Range<u8> = blake3::OUT_LEN as u8..u8::MAX;
pub const IV_SIZE_RANGE: Range<u8> = argon2::MIN_SALT_LEN as u8..argon2::MAX_SALT_LEN as u8;
pub const TAG_SIZE_RANGE: Range<u8> = 16..u8::MAX;

pub const MIN_KEY_SIZE: usize = 16;
