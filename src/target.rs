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

use std::fmt;
use std::str;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
pub enum Target {
    Encrypt,
    Decrypt,
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Encrypt => write!(formatter, "encrypt"),
            Self::Decrypt => write!(formatter, "decrypt"),
        }
    }
}

impl str::FromStr for Target {
    type Err = String;

    fn from_str(action: &str) -> Result<Self, Self::Err> {
        match action.to_lowercase().as_str() {
            "encrypt" => Ok(Target::Encrypt),
            "decrypt" => Ok(Target::Decrypt),
            _ => Err(format!(
                "Unknown action '{}', the options are '{}' & '{}'!",
                action,
                Target::Encrypt,
                Target::Decrypt
            )),
        }
    }
}

impl Default for Target {
    fn default() -> Self {
        Self::Encrypt
    }
}
