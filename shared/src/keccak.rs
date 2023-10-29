//! A `const fn` Keccak-256 implementation.

use core::mem;

/// Returns the Keccak-256 digest of the specified bytes.
pub const fn v256(data: &[u8]) -> [u8; 32] {
    V256::new().absorb(data).squeeze()
}

/// The Keccak-p\[1600,24\] permutation function (also referred to as
/// Keccak-f\[1600\]). This is an implementation of Algorithm 7 from FIPS 202
/// for b = 1600 and nr = 24.
const fn keccakf(mut a: [u64; 25]) -> [u64; 25] {
    let mut b = [0; 25];
    let mut c = [0; 5];
    let mut d = [0; 5];

    let mut i = 0;
    while i < RC.len() {
        let rc = RC[i];
        i += 1;

        // π ∘ ρ ∘ θ:
        c[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
        c[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
        c[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
        c[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
        c[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
        d[0] = c[4] ^ c[1].rotate_left(1);
        d[1] = c[0] ^ c[2].rotate_left(1);
        d[2] = c[1] ^ c[3].rotate_left(1);
        d[3] = c[2] ^ c[4].rotate_left(1);
        d[4] = c[3] ^ c[0].rotate_left(1);
        b[0] = a[0] ^ d[0];
        b[1] = (a[6] ^ d[1]).rotate_left(44);
        b[2] = (a[12] ^ d[2]).rotate_left(43);
        b[3] = (a[18] ^ d[3]).rotate_left(21);
        b[4] = (a[24] ^ d[4]).rotate_left(14);
        b[5] = (a[3] ^ d[3]).rotate_left(28);
        b[6] = (a[9] ^ d[4]).rotate_left(20);
        b[7] = (a[10] ^ d[0]).rotate_left(3);
        b[8] = (a[16] ^ d[1]).rotate_left(45);
        b[9] = (a[22] ^ d[2]).rotate_left(61);
        b[10] = (a[1] ^ d[1]).rotate_left(1);
        b[11] = (a[7] ^ d[2]).rotate_left(6);
        b[12] = (a[13] ^ d[3]).rotate_left(25);
        b[13] = (a[19] ^ d[4]).rotate_left(8);
        b[14] = (a[20] ^ d[0]).rotate_left(18);
        b[15] = (a[4] ^ d[4]).rotate_left(27);
        b[16] = (a[5] ^ d[0]).rotate_left(36);
        b[17] = (a[11] ^ d[1]).rotate_left(10);
        b[18] = (a[17] ^ d[2]).rotate_left(15);
        b[19] = (a[23] ^ d[3]).rotate_left(56);
        b[20] = (a[2] ^ d[2]).rotate_left(62);
        b[21] = (a[8] ^ d[3]).rotate_left(55);
        b[22] = (a[14] ^ d[4]).rotate_left(39);
        b[23] = (a[15] ^ d[0]).rotate_left(41);
        b[24] = (a[21] ^ d[1]).rotate_left(2);

        // ι ∘ χ:
        a[0] = b[0] ^ (!b[1] & b[2]) ^ rc;
        a[1] = b[1] ^ (!b[2] & b[3]);
        a[2] = b[2] ^ (!b[3] & b[4]);
        a[3] = b[3] ^ (!b[4] & b[0]);
        a[4] = b[4] ^ (!b[0] & b[1]);
        a[5] = b[5] ^ (!b[6] & b[7]);
        a[6] = b[6] ^ (!b[7] & b[8]);
        a[7] = b[7] ^ (!b[8] & b[9]);
        a[8] = b[8] ^ (!b[9] & b[5]);
        a[9] = b[9] ^ (!b[5] & b[6]);
        a[10] = b[10] ^ (!b[11] & b[12]);
        a[11] = b[11] ^ (!b[12] & b[13]);
        a[12] = b[12] ^ (!b[13] & b[14]);
        a[13] = b[13] ^ (!b[14] & b[10]);
        a[14] = b[14] ^ (!b[10] & b[11]);
        a[15] = b[15] ^ (!b[16] & b[17]);
        a[16] = b[16] ^ (!b[17] & b[18]);
        a[17] = b[17] ^ (!b[18] & b[19]);
        a[18] = b[18] ^ (!b[19] & b[15]);
        a[19] = b[19] ^ (!b[15] & b[16]);
        a[20] = b[20] ^ (!b[21] & b[22]);
        a[21] = b[21] ^ (!b[22] & b[23]);
        a[22] = b[22] ^ (!b[23] & b[24]);
        a[23] = b[23] ^ (!b[24] & b[20]);
        a[24] = b[24] ^ (!b[20] & b[21]);
    }
    a
}

/// Pre-computed RC values per round index for the ι step. See Algorithms 5 and
/// 6 from FIPS 202.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The Keccak sponge function is defined in Algorithm 8 from FIPS 202. The
/// implementation here is split between the [`Self::absorb()`] and
/// [`Self::squeeze()`] and specialized for Keccak-256.
#[derive(Clone, Copy, Default)]
pub struct V256 {
    /// The 1600-bit/200-byte state of the sponge, stored as an array of u64s
    /// ready for the [`keccakf`] permutation function.
    s: [u64; 25],
    /// The position in bytes to continue writing to when [`V256::absorb_`]-ing.
    pos: usize,
}

impl V256 {
    /// The number of input bytes processed or output bytes generated at a time.
    const RATE: usize = 136;

    /// The domain separation byte for the sponge construction instance
    /// **including** the first bit of padding. Different domain separators are
    /// used for hashing and XOFs. See Table 6 from FIPS 202.
    const DS: u8 = 0x01;

    /// Creates a new sponge with the specified rate and domain separator.
    pub const fn new() -> Self {
        Self { s: [0; 25], pos: 0 }
    }

    /// Absorb some data into the sponge.
    pub const fn absorb(mut self, data: &[u8]) -> Self {
        const N: usize = mem::size_of::<u64>();

        let mut remaining = data.len();
        let mut ptr = data.as_ptr();

        // SAFETY: We are copying data from `data` to the sponge, which is safe.
        // Note the use of un-aligned reads, which is required to not make this
        // undefined behaviour when `data` is not aligned to a `u64`.
        unsafe {
            while remaining > 0 {
                debug_assert!(self.pos < Self::RATE);

                let n = if self.pos % N == 0 && remaining >= N {
                    // fast-path: if we are at a 64-bit boundary and have a full
                    // 64-bit word to read.
                    self.s[self.pos / N] ^= ptr.cast::<u64>().read_unaligned().to_le();
                    N
                } else {
                    // slow-path.
                    let mut buf = [0; N];
                    let o = self.pos % N;
                    let n = N - o;
                    let n = if n < remaining { n } else { remaining };
                    let mut i = 0;
                    while i < n {
                        buf[o + i] = ptr.add(i).read();
                        i += 1;
                    }
                    self.s[self.pos / N] ^= u64::from_le_bytes(buf);
                    n
                };

                self.pos += n;
                if self.pos == Self::RATE {
                    self.s = keccakf(self.s);
                    self.pos = 0;
                }

                remaining -= n;
                ptr = ptr.add(n);
            }
        }

        self
    }

    /// Write the domain separation string, pad the input to the sponge, and
    /// squeeze the digest from the sponge. See Appendix B.2 from FIPS 202.
    pub const fn squeeze(mut self) -> [u8; 32] {
        const N: usize = mem::size_of::<u64>();
        macro_rules! xor_byte {
            ($i:expr, $b:expr) => {{
                let (i, b) = ($i, $b);
                let mut buf = [0; N];
                buf[i % N] = b;
                self.s[i / N] ^= u64::from_le_bytes(buf);
            }};
        }

        xor_byte!(self.pos, Self::DS);
        xor_byte!(Self::RATE - 1, 0x80);
        self.s = keccakf(self.s);

        // SAFETY: transmuting between integer arrays and byte arrays of the
        // same size is safe.
        unsafe {
            mem::transmute([
                self.s[0].to_le(),
                self.s[1].to_le(),
                self.s[2].to_le(),
                self.s[3].to_le(),
            ])
        }
    }
}
