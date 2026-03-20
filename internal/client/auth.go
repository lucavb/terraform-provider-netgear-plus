package client

import (
	"crypto/md5" //nolint:gosec // Device protocol requires MD5.
	"encoding/hex"
)

// Merge alternates characters from each string, matching the switch login KDF.
func Merge(left, right string) string {
	result := make([]byte, 0, len(left)+len(right))
	maxLen := len(left)
	if len(right) > maxLen {
		maxLen = len(right)
	}

	for idx := 0; idx < maxLen; idx++ {
		if idx < len(left) {
			result = append(result, left[idx])
		}
		if idx < len(right) {
			result = append(result, right[idx])
		}
	}

	return string(result)
}

// PasswordKDF returns md5(merge(password, rand)) for GS108Ev3 login.
func PasswordKDF(password, rand string) string {
	sum := md5.Sum([]byte(Merge(password, rand))) //nolint:gosec // Device protocol requires MD5.
	return hex.EncodeToString(sum[:])
}
