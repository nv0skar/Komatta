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

use crate::keys::Signing;

use std::{fmt, fmt::Display, ops::Range};

use argon2;
use blake3;
use pqcrypto::sign::dilithium5;

pub struct Size<T> {
    pub name: &'static str,
    pub default: T,
    pub behaviour: Behaviour,
}

pub enum Behaviour {
    Fixed,
    Ranged(Range<u16>),
    Unfixed,
}

impl Size<u16> {
    const fn new(name: &'static str, default: u16, behaviour: Behaviour) -> Self {
        Self {
            name,
            default,
            behaviour,
        }
    }

    pub fn check(&self, value: u16) -> Result<(), String> {
        if !{
            match &self.behaviour {
                Behaviour::Fixed => self.default == value,
                Behaviour::Ranged(range) => range.contains(&value),
                Behaviour::Unfixed => true,
            }
        } {
            Err(format!(
                "Invalid value {} at '{}'. Valid values: {}",
                value, self.name, self
            ))
        } else {
            Ok(())
        }
    }
}

impl Display for Size<u16> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &self.behaviour {
            Behaviour::Fixed => write!(formatter, "Value: {}", self.default),
            Behaviour::Ranged(range) => write!(
                formatter,
                "{}..{} (Default: {})",
                range.start, range.end, self.default
            ),
            Behaviour::Unfixed => write!(formatter, "Default: {}", self.default),
        }
    }
}

pub const IV_SIZE: Size<u16> = Size::new("IV Size", 8, Behaviour::Ranged(8..u16::MAX));
pub const BLOCK_SIZE: Size<u16> = Size::new("Block Size", 64, Behaviour::Ranged(4..u16::MAX));
pub const SIGNATURE_SIZE: Size<u16> = Size::new(
    "Signature Size",
    dilithium5::signature_bytes() as u16,
    Behaviour::Fixed,
);

pub const KEYED_HASH_SIZE: Size<u16> = Size::new(
    "Keyed Hash Size",
    32,
    Behaviour::Ranged(blake3::OUT_LEN as u16..u16::MAX),
);

pub const CRYPT_KEY_SIZE: Size<u16> = Size::new(
    "Crypt Key Size",
    CRYPT_KEY_SIZE_VALUE,
    Behaviour::Ranged(16..u16::MAX),
);
pub const CRYPT_KEY_SIZE_VALUE: u16 = 16;
pub const SIGNING_KEY_SIZE: Signing::Keys<Size<u16>> = Signing::Keys {
    secret: Size::new(
        "Signing Secret Key Size",
        dilithium5::secret_key_bytes() as u16,
        Behaviour::Fixed,
    ),
    public: Size::new(
        "Signing Public Key Size",
        dilithium5::public_key_bytes() as u16,
        Behaviour::Fixed,
    ),
};

pub const SALT_SIZE: Size<u16> = Size::new(
    "Salt Size",
    8,
    Behaviour::Ranged(argon2::MIN_SALT_LEN as u16..u16::MAX),
);
