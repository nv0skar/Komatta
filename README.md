<h1 style="color:#814EEF;text-shadow: -2px 2px #360D8D;font-size:40px", align="center">こま</h1>

<h4 align="center">A cryptosystem 💿</h4>

## <a name="what"></a>何？ 🧪
こま (also called **Komatta**) is an utility / library which implements a ~~fast~~ (yet to be tested) cryptosystem: encryption, integrity (signed or unsigned).

## <a name="how"></a>どうやって？ 🤔
As its primitives, it uses `Blake3` for the `keyed hash` function (not using the `Blake3`'s native keyed hash) and `Argon2`.

`subkey` is an `Argon2` of `random salt || symmetric key`
### <a name="howCypher"></a>Cypher 🔡
It's symmetric and variable-length.
Here is a brief explanation of how the mechanism works:
1. A random `iv` is generated
2. Input is divided in blocks of length equal to the `block size` to get the `plain blocks` 
3. Create an array of byte arrays `cyphered blocks` where the encrypted blocks will be stored
4. Enumerate and iterate `plain blocks` (`offset`, `block`):
   1. Get the `last cyphered block` from `cyphered blocks` (if the array is empty, this value will be the keyed hash of `iv` using `subkey` as the key)
   2. Calculate the keyed hash of `offset` using `sub key` as the key to get the `counter`
   3. `counter` will be now equal to `counter ⨁ last cyphered block` (if `counter > last cyphered block`, `last cyphered block` is repeated until both are the same length) (if `counter < last cyphered block`, `last cyphered block`'s latest elements will be popped out of the array until both are the same length)
   4. Calculate `block ⨁ counter` to get `cyphertext` (if `block length > counter length`, `counter` is repeated until both are the same length) (if `block length < counter length`, `counter`'s latest elements will be popped out of the array until both are the same length)
   5. Push `cyphertext` to `cyphered blocks`
5. Concatenate all the `cyphered blocks`'s arrays

### <a name="howIntegrity"></a>Integrity 🔒
`input` is `block size || integrity kind || iv || cyphertext`
#### <a name="howIntegritySigned"></a>Signed
Signatures are generated using `Dilithium5` with an `input` and a  previously generated `keypair`.
Using signed integrity can achieve:
- Integrity
- Authenticity
#### <a name="howIntegrityUnsigned"></a>Unsigned
Unsigned integrity is achieved by calculating a keyed hash of `input` using `subkey` as the key. Using unsigned integrity can achieve:
- Integrity
- ~~Authenticity~~

## <a name="development"></a>発達 🧑‍💻
### <a name="developmentTODO"></a>リストを行う 🛸
わからない！