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

use Komatta::{keys::Keys, ops::randomness, target::Target, Crypt, Integrity};

use criterion::{criterion_group, criterion_main, Criterion};

pub fn crypt(c: &mut Criterion) {
    let input = randomness(128);

    let mut crypt = Crypt::new(
        Target::Encrypt,
        Keys::new(None, None, true).unwrap(),
        None,
        None,
        input.clone(),
        Integrity::Signed(None),
    );

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut newCrypt = crypt.clone();
            let _ = newCrypt.process();
        })
    });

    crypt.input = crypt.process().unwrap();

    crypt.target = Target::Decrypt;

    crypt.keys = Keys::from(crypt.keys.public().unwrap());

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut newCrypt = crypt.clone();
            let _ = newCrypt.process();
        })
    });
}

criterion_group!(benches, crypt);
criterion_main!(benches);
