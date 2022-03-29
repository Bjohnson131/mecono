package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// A string in hexadecimal form.
type HexString string

// A string in Base64 form
type Base64String string

func BytesToHex(bytes []byte) HexString {
	return HexString(hex.EncodeToString(bytes))
}

func BytesToBase64(bytes []byte) Base64String {
	return Base64String(base64.StdEncoding.EncodeToString(bytes))
}

func MiniHexString(hexString HexString) string {
	if len(hexString) < 6 {
		return "UNK-NWN"
	}

	return fmt.Sprintf("%s-%s", hexString[0:3], hexString[len(hexString)-3:])
}
