// SPDX-FileCopyrightText: 2021 Oleksiy Voronin <me@ovoronin.info>
// SPDX-License-Identifier: MIT

package gotp

import (
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
)

// OTP defines common functions for the one-time passwords
type OTP interface {
	GenerateOTP(counter int64) string
	Verify(otp string, counter int64) bool
	ProvisioningUrl(label string, issuer string) string
}

func adjustForSha1(key []byte) []byte {
	if len(key) > sha1.BlockSize { // if key is longer than block size
		keyHash := sha1.Sum(key)
		key = keyHash[:]
	}
	if len(key) < sha1.BlockSize { // pad the key if needed
		key = append(key, make([]byte, sha1.BlockSize-len(key))...)
	}
	return key
}

func encodeKey(key []byte) string {
	encoded := base32.HexEncoding.EncodeToString(key)
	eqIdx := strings.Index(encoded, "=")
	if eqIdx >= 0 {
		encoded = encoded[:eqIdx]
	}
	return encoded
}

func decodeKey(key string) ([]byte, error) {
	missingPadding := len(key) % 8
	if missingPadding != 0 {
		key = key + strings.Repeat("=", 8-missingPadding)
	}
	return base32.HexEncoding.DecodeString(key)
}

const (
	typeHotp      = "hotp"
	typeTotp      = "totp"
	otpAuthSheme  = "otpauth"
	secretKey     = "secret"
	issuerKey     = "issuer"
	digitsKey     = "digits"
	periodKey     = "period"
	defaultDigits = 6
)

func generateProvisioningUrl(otpType string, accountName string, issuer string, digits int, key []byte, extra url.Values) string {
	extra.Add(secretKey, encodeKey(key))
	extra.Add(issuerKey, issuer)
	if digits != defaultDigits {
		extra.Add(digitsKey, fmt.Sprintf("%d", digits))
	}
	u := url.URL{
		Scheme:   otpAuthSheme,
		Host:     otpType,
		Path:     url.PathEscape(issuer) + ":" + url.PathEscape(accountName),
		RawQuery: extra.Encode(),
	}
	return u.String()
}
