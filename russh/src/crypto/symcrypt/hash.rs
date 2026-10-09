//! SHA-1 and SHA-2 for the SymCrypt backend (`symcrypt::hash`), used for
//! exchange hashes and key derivation.

use symcrypt::hash::{
    SHA1_RESULT_SIZE, SHA256_RESULT_SIZE, SHA384_RESULT_SIZE, SHA512_RESULT_SIZE, sha1, sha256,
    sha384, sha512,
};

use crate::crypto::Hash;

macro_rules! hash {
    ($name:ident, $digest:ident, $len:ident) => {
        pub(crate) struct $name;

        impl Hash for $name {
            type Output = [u8; $len];

            fn digest(data: &[u8]) -> Self::Output {
                $digest(data)
            }
        }
    };
}

// SHA-1 is only part of the provider contract (the shared
// `diffie-hellman-*-sha1` code names it); this backend offers no SHA-1 kex.
hash!(Sha1, sha1, SHA1_RESULT_SIZE);
hash!(Sha256, sha256, SHA256_RESULT_SIZE);
hash!(Sha384, sha384, SHA384_RESULT_SIZE);
hash!(Sha512, sha512, SHA512_RESULT_SIZE);

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    const ABC: &[u8] = b"abc";
    /// The two-block messages of FIPS 180-2: 448 bits for SHA-1 and SHA-256,
    /// 896 bits for SHA-384 and SHA-512.
    const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const MSG_896: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
        hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    fn million_a() -> Vec<u8> {
        vec![b'a'; 1_000_000]
    }

    // FIPS 180-2 examples, plus the empty message.
    #[test]
    fn sha1_known_answers() {
        assert_eq!(
            Sha1::digest(b""),
            hex!("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
        assert_eq!(
            Sha1::digest(ABC),
            hex!("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            Sha1::digest(MSG_448),
            hex!("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
        );
        assert_eq!(
            Sha1::digest(&million_a()),
            hex!("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            Sha256::digest(b""),
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            Sha256::digest(ABC),
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            Sha256::digest(MSG_448),
            hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
        assert_eq!(
            Sha256::digest(&million_a()),
            hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn sha384_known_answers() {
        assert_eq!(
            Sha384::digest(b""),
            hex!(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                "274edebfe76f65fbd51ad2f14898b95b"
            )
        );
        assert_eq!(
            Sha384::digest(ABC),
            hex!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7"
            )
        );
        assert_eq!(
            Sha384::digest(MSG_896),
            hex!(
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
                "fcc7c71a557e2db966c3e9fa91746039"
            )
        );
        assert_eq!(
            Sha384::digest(&million_a()),
            hex!(
                "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
                "07b8b3dc38ecc4ebae97ddd87f3d8985"
            )
        );
    }

    #[test]
    fn sha512_known_answers() {
        assert_eq!(
            Sha512::digest(b""),
            hex!(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            Sha512::digest(ABC),
            hex!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        assert_eq!(
            Sha512::digest(MSG_896),
            hex!(
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            )
        );
        assert_eq!(
            Sha512::digest(&million_a()),
            hex!(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }
}
