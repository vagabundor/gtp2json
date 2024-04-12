package gtp2ie

import "fmt"

// DecodeBCD converts packed BCD-encoded bytes into a decimal string.
// It reads two digits per byte, halting on a 0xF special symbol.
// Digits are processed in big-endian order.
func DecodeBCD(content []byte) (string, error) {
	var decoded string

	for _, b := range content {
		// First digit
		firstDigit := b & 0x0F
		if firstDigit == 0xF {
			break
		}
		decoded += fmt.Sprintf("%d", firstDigit)

		// Second digit
		secondDigit := (b >> 4) & 0x0F
		if secondDigit == 0xF {
			break
		}
		decoded += fmt.Sprintf("%d", secondDigit)
	}

	return decoded, nil
}
