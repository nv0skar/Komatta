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

use clap::Arg;

#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    pub block_size: u8,
    pub keyed_hash_size: u8,
    pub iv_size: u8,
    pub tag_size: u8,
}

impl Parameters {
    pub fn check(&self) {
        assert!(crate::defaults::BLOCK_SIZE_RANGE.contains(&self.block_size));
        assert!(crate::defaults::KEYED_HASH_SIZE_RANGE.contains(&self.keyed_hash_size));
        assert!(crate::defaults::IV_SIZE_RANGE.contains(&self.iv_size));
        assert!(crate::defaults::TAG_SIZE_RANGE.contains(&self.tag_size));
    }

    pub fn paramsLen() -> usize {
        let defaults: Vec<u8> = Self::default().into();
        defaults.len()
    }
}

impl Parameters {
    pub fn format(arg: Arg) -> Arg {
        arg.clone()
            .long(arg.clone().get_id())
            .takes_value(true)
            .required(false)
            .value_parser(clap::value_parser!(u8))
    }
}

impl Into<Vec<u8>> for Parameters {
    fn into(self) -> Vec<u8> {
        vec![
            self.block_size,
            self.keyed_hash_size,
            self.iv_size,
            self.tag_size,
        ]
    }
}

impl From<Vec<u8>> for Parameters {
    fn from(parameters: Vec<u8>) -> Self {
        Self {
            block_size: *parameters.get(0).unwrap(),
            keyed_hash_size: *parameters.get(1).unwrap(),
            iv_size: *parameters.get(2).unwrap(),
            tag_size: *parameters.get(3).unwrap(),
        }
    }
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            block_size: crate::defaults::BLOCK_SIZE,
            keyed_hash_size: crate::defaults::KEYED_HASH_SIZE,
            iv_size: crate::defaults::IV_SIZE,
            tag_size: crate::defaults::TAG_SIZE,
        }
    }
}
