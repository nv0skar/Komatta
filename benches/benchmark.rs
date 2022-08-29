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

use Komatta::{actions::Action, parameters::Parameters, Cypher};

use criterion::{criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};

pub fn benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();

    let mut crypt = Cypher {
        action: Action::Encrypt,
        key: (0..u8::MAX).map(|_| rng.gen_range(0..u8::MAX)).collect(),
        input: (0..u8::MAX).map(|_| rng.gen_range(0..u8::MAX)).collect(),
        parameters: Some(Parameters {
            block_size: u8::MAX - 1,
            keyed_hash_size: u8::MAX - 1,
            iv_size: u8::MAX - 1,
            tag_size: u8::MAX - 1,
        }),
    };

    println!(
        "Benchmarking with the following parameters: {:?}",
        crypt.parameters.unwrap()
    );

    c.bench_function("encrypt", |b| b.iter(|| crypt.process()));

    crypt.input = crypt.process().unwrap();
    crypt.action = Action::Decrypt;

    c.bench_function("decrypt", |b| b.iter(|| crypt.process()));
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
