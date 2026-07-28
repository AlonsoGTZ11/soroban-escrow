use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

/// Computes the Merkle root hash using SHA-256 for a list of leaf data.
///
/// # Arguments
///
/// * `leaves` - A slice of byte slices representing the leaf nodes
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::merkle_root;
///
/// let leaves: Vec<&[u8]> = vec![b"leaf1", b"leaf2", b"leaf3"];
/// let root = merkle_root(&leaves);
/// assert!(!root.is_empty());
/// ```
///
/// Empty input returns empty string:
///
/// ```
/// use soroban_toolkit::hash::merkle_root;
///
/// let empty_leaves: Vec<&[u8]> = vec![];
/// let root = merkle_root(&empty_leaves);
/// assert_eq!(root, "");
/// ```
pub fn merkle_root(leaves: &[&[u8]]) -> String {
    if leaves.is_empty() {
        return String::new();
    }

    let mut current_level: Vec<Vec<u8>> = leaves.iter().map(|leaf| sha256_bytes(leaf)).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                left
            };

            let mut combined = left.to_vec();
            combined.extend_from_slice(right);
            let hashed = sha256_bytes(&combined);
            next_level.push(hashed);

            i += 2;
        }

        current_level = next_level;
    }

    hex::encode(&current_level[0])
}

type HmacSha256 = Hmac<Sha256>;

/// Returns the lowercase hexadecimal string representation of the SHA-256 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the data to hash.
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::sha256_hex;
///
/// let result = sha256_hex(b"hello");
/// assert_eq!(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
///
/// let empty_result = sha256_hex(b"");
/// assert_eq!(empty_result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Returns the raw SHA-256 hash bytes of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the data to hash.
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::sha256_bytes;
///
/// let result = sha256_bytes(b"hello");
/// assert_eq!(result.len(), 32);
///
/// // Known SHA-256 bytes for empty string
/// let empty_result = sha256_bytes(b"");
/// assert_eq!(
///     empty_result,
///     vec![
///         0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
///         0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
///         0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
///         0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
///     ]
/// );
/// ```
pub fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Returns the lowercase hexadecimal representation of the SHA-512 hash of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the data to hash.
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::sha512_hex;
///
/// let result = sha512_hex(b"hello");
/// assert_eq!(
///     result,
///     "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
/// );
///
/// let empty_result = sha512_hex(b"");
/// assert_eq!(
///     empty_result,
///     "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
/// );
/// ```
pub fn sha512_hex(data: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Returns the raw SHA-512 hash bytes of the input data.
///
/// # Arguments
///
/// * `data` - A byte slice containing the data to hash.
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::sha512_bytes;
///
/// let result = sha512_bytes(b"hello");
/// assert_eq!(result.len(), 64);
/// assert_eq!(result[0], 0x9b);
///
/// let empty_result = sha512_bytes(b"");
/// assert_eq!(
///     empty_result,
///     vec![
///         0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd,
///         0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
///         0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
///         0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
///         0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
///         0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
///         0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
///         0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
///     ]
/// );
/// ```
pub fn sha512_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Returns BLAKE3 hash as hex string
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::blake3_hex;
///
/// let result = blake3_hex(b"hello");
/// assert_eq!(result, "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f");
/// ```
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3::hash(data).as_bytes())
}

/// Returns BLAKE3 hash as bytes
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::blake3_bytes;
/// use hex;
///
/// let result = blake3_bytes(b"hello");
/// let expected_hex = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
/// assert_eq!(hex::encode(result), expected_hex);
/// ```
pub fn blake3_bytes(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

/// Returns double SHA-256 hash as hex string (used in blockchain contexts like Bitcoin)
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::double_sha256;
///
/// let result = double_sha256(b"hello");
/// assert_eq!(result, "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
/// ```
pub fn double_sha256(data: &[u8]) -> String {
    let first = sha256_bytes(data);
    sha256_hex(&first)
}

/// Returns HMAC-SHA256 signature as hex-encoded string
///
/// # Examples
///
/// ```
/// use soroban_toolkit::hash::hmac_sha256;
///
/// let key = b"secret_key";
/// let message = b"hello world";
/// let signature = hmac_sha256(key, message);
/// assert_eq!(signature, "cf1a418afaafc798df48fd804a2abf6970283afd8c40b41f818ad9b6ca4f8ca8");
/// ```
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> String {
    // Create HMAC instance; HMAC-SHA256 theoretically supports any key size.
    // If key validation fails for some reason, we use a pre-computed default key.
    let mut mac = HmacSha256::new_from_slice(key).unwrap_or_else(|_| {
        HmacSha256::new_from_slice(&[0u8; 32]).expect("hardcoded 32-byte key is always valid")
    });
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// Timing-safe comparison of two byte slices
///
/// This function performs a constant-time comparison to prevent timing attacks.
/// When comparing sensitive data like hashes or cryptographic signatures, a naive
/// byte-by-byte comparison using `==` can leak information through timing differences:
/// - Early mismatch exits immediately (fast)
/// - Full matches require comparing all bytes (slow)
///
/// An attacker can measure these timing differences to infer how many bytes match,
/// potentially recovering the correct value through repeated attacks.
///
/// This implementation uses XOR operations and bitwise OR to ensure all bytes are
/// compared regardless of their values, taking constant time regardless of where
/// mismatches occur.
///
/// # Arguments
/// * `a` - First byte slice to compare
/// * `b` - Second byte slice to compare
///
/// # Returns
/// `true` if both slices are equal, `false` otherwise
///
/// # Example
/// ```
/// use soroban_toolkit::hash::secure_compare;
/// let hash1 = [0xab, 0xcd];
/// let hash2 = [0xab, 0xcd];
/// assert!(secure_compare(&hash1, &hash2));
/// ```
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_empty_input() {
        let leaves: Vec<&[u8]> = vec![];
        assert_eq!(merkle_root(&leaves), "");
    }

    #[test]
    fn test_merkle_root_single_leaf() {
        let leaves: Vec<&[u8]> = vec![b"test"];
        let expected = sha256_hex(b"test");
        assert_eq!(merkle_root(&leaves), expected);
    }

    #[test]
    fn test_merkle_root_two_leaves() {
        let leaf1 = b"leaf1";
        let leaf2 = b"leaf2";
        let hash1 = sha256_bytes(leaf1);
        let hash2 = sha256_bytes(leaf2);
        let mut combined = hash1;
        combined.extend_from_slice(&hash2);
        let expected = sha256_hex(&combined);
        assert_eq!(merkle_root(&[leaf1, leaf2]), expected);
    }

    #[test]
    fn test_merkle_root_three_leaves() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let root = merkle_root(&leaves);
        assert!(!root.is_empty());
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_sha256_known_value() {
        let result = sha256_hex(b"hello");
        assert_eq!(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hex_empty() {
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_bytes_empty() {
        let result = sha256_bytes(b"");
        let expected = vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha256_bytes_known_value() {
        let result = sha256_bytes(b"hello");
        let expected = vec![
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_hex_known_value() {
        let result = sha512_hex(b"hello");
        assert_eq!(
            result,
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
        );
    }

    #[test]
    fn test_sha512_hex_empty() {
        let result = sha512_hex(b"");
        assert_eq!(
            result,
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_sha512_bytes_known_value() {
        let result = sha512_bytes(b"hello");
        let expected = vec![
            0x9b, 0x71, 0xd2, 0x24, 0xbd, 0x62, 0xf3, 0x78, 0x5d, 0x96, 0xd4, 0x6a, 0xd3, 0xea,
            0x3d, 0x73, 0x31, 0x9b, 0xfb, 0xc2, 0x89, 0x0c, 0xaa, 0xda, 0xe2, 0xdf, 0xf7, 0x25,
            0x19, 0x67, 0x3c, 0xa7, 0x23, 0x23, 0xc3, 0xd9, 0x9b, 0xa5, 0xc1, 0x1d, 0x7c, 0x7a,
            0xcc, 0x6e, 0x14, 0xb8, 0xc5, 0xda, 0x0c, 0x46, 0x63, 0x47, 0x5c, 0x2e, 0x5c, 0x3a,
            0xde, 0xf4, 0x6f, 0x73, 0xbc, 0xde, 0xc0, 0x43,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha512_bytes_empty() {
        let result = sha512_bytes(b"");
        let expected = vec![
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_double_sha256() {
        let result = double_sha256(b"hello");
        assert_eq!(
            result,
            "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50"
        );
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_secure_compare_equal() {
        assert!(secure_compare(b"hello", b"hello"));
    }

    #[test]
    fn test_secure_compare_not_equal() {
        assert!(!secure_compare(b"hello", b"world"));
    }

    #[test]
    fn test_hmac_sha256_test_vector_1() {
        // Test vector from RFC 4231
        let key = [0x0b; 20];
        let message = b"Hi There";
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hmac_sha256(&key, message), expected);
    }

    #[test]
    fn test_hmac_sha256_test_vector_2() {
        // Test vector from RFC 4231
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assert_eq!(hmac_sha256(key, message), expected);
    }

    #[test]
    fn test_hmac_sha256_test_vector_3() {
        // Test vector from RFC 4231
        let key = [0xaa; 20];
        let message = [0xdd; 50];
        let expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
        assert_eq!(hmac_sha256(&key, &message), expected);
    }
}
