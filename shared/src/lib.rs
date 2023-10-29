//! Shared Rust modules.

#![cfg_attr(not(test), no_std)]

pub mod hex;
pub mod keccak;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak256() {
        for (data, digest) in [
            (
                "",
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            ),
            (
                "abc",
                "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
            ),
            (
                "abcdefgh",
                "48624fa43c68d5c552855a4e2919e74645f683f5384f72b5b051b71ea41d4f2d",
            ),
            (
                "abcdefghi",
                "34fb2702da7001bf4dbf26a1e4cf31044bd95b85e1017596ee2d23aedc90498b",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                 hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "f519747ed599024f3882238e5ab43960132572b7345fbeb9a90769dafd21ad67",
            ),
            (
                "'UNIX was not designed to stop its users from doing stupid things, \
                 as that would also stop them from doing clever things' - Doug Gwyn",
                "9b4d53fcd92c62990df9b6cf32f92d14855990d715324071bf2a1b4b6e96fee7",
            ),
            (
                "'Life is too short to run proprietary software' - Bdale Garbee",
                "67ccea83aa6447e008dc6a1011fc7fcd9a80f7aabcea2e0bf6577389a3492ecb",
            ),
            (
                "'The central enemy of reliability is complexity.' - Geer et al",
                "b1b92a4a918ea3b968dcaae18580ace83ad9813f2a7c5add4345a29f9050b6cb",
            ),
            (
                "4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242\
                 4242424242424242424242424242424242424242424242424242424242424242",
                "de823a8230f190b2f5f731fbb1257a8740e3752c7df2a8a96cd2ccd13903a36a",
            ),
        ] {
            assert_eq!(
                hex::encode::<32, 66>(&keccak::v256(data.as_bytes()), hex::Alphabet::Lower)
                    .as_bytes_str(),
                digest
            );
        }
    }
}
