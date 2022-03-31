package encoding

import "crypto/sha256"

type Sha256HashBytes []byte

func BytesToSha256Hash(plainbytes []byte) Sha256HashBytes {
	sum := sha256.Sum256(plainbytes)
	return Sha256HashBytes(sum[:])
}

// Convenience method to hash plainbytes, then encode into a hex string.
func BytesToSha256HashHexString(plainbytes []byte) HexString {
	hashbytes := BytesToSha256Hash(plainbytes)
	return BytesToHex(hashbytes)
}

// Convenience method to hash plainbytes, then encode into a Base64 string.
func BytesToSha256HashBase64String(plainbytes []byte) Base64String {
	hashbytes := BytesToSha256Hash(plainbytes)
	return BytesToBase64(hashbytes)
}
