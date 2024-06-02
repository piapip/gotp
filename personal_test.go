package gotp_test

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSmt(t *testing.T) {
	var (
		sharedSecret = []byte("SHARED_KEYWORD_OVER_HERE")
		TX           = int64(30)
		T0           = int64(0)
		passwordLen  = 10 // the length of the One-time password.
	)

	// TOPT = HOPT(Key, timecounter) = Truncate(HMAC_SHA512)
	// 1. Generate HMAC_SHA512
	//    1.1. If I'm paranoid, it's better to pad the sharedSecret with 00000
	//         so it can have the required length of the SHA algorithm,
	//         but it seems like the library already does that for me.
	//    1.2. Make a hmac generator using the key_bytes and the SHA512 algorithm as the input.
	//    1.3. Calculate the counter by using the time formula, and convert the counter to bytes.
	//    1.4. Hash the counter.
	// 2. Get the offset by using the last 4 BITS (NOT BYTES) of the generated HMAC_SHA512.
	//    OFFSET = int_value of (the HMAC_SHA512's last bytes)
	// 3. Get the 4 bytes starting from the offset, that's our wanted one time password.
	//    For example:
	//      Bytes value is:
	//      1f|86|98|69|0e|02|ca|16|61|85|50|ef|7f|19|da|8e|94|5b|55|5a
	//      The last byte is 5a. The last 4 bits is 0xa ~ 10.
	//      So it's
	//      1f|86|98|69|0e|02|ca|16|61|85|50|ef|7f|19|da|8e|94|5b|55|5a
	//                                    -----------
	//      Our wanted value is 0x50ef7f19.
	// 4. Convert the wanted value to int, and take modulo based on how many digits that we want.
	//    I want 10, so (0x50ef7f19 --> int) % 10^10. (10_000_000_000)
	//    0x50ef7f19 to int is 1 357 872 921, so that's my 10-digit OTP.
	//    If I want 6-digit OTP, then it's 872 921.

	// 1.
	// 1.2
	hmacGenerator := hmac.New(crypto.SHA512.New, sharedSecret)

	// 1.3.
	// Apply the formula for the counter.
	// In the actual implementation, this counter should be incremented by 1 right after this.
	//  defer func() {counter+=1}
	// so the next password request will be done with new counter, to generate a new password.
	counter := (time.Now().Unix() - T0) / TX

	// Convert the counter to bytes.
	buf := new(bytes.Buffer)
	// The MSB in our cases is to the left most, aka the natural way,
	// like how we read this explanation from left to right on the line.
	// so BigEndian,
	// I honestly don't understand when to use LittleEndian.
	err := binary.Write(buf, binary.BigEndian, counter)
	assert.NoError(t, err)
	counterBytes := buf.Bytes()

	// 1.4
	hmacGenerator.Write(counterBytes)
	genHash := hmacGenerator.Sum([]byte{})
	fmt.Printf("gen: %x\n", genHash)

	// 2.
	lastByte := genHash[len(genHash)-1]
	lastBit := lastByte & 0x0f
	offset := int(lastBit)
	fmt.Printf("last bytes: %x\n", lastByte)
	fmt.Printf("offset: %x\n", offset)

	// 3.
	maskedOTPBinary := (int(genHash[offset]&0x7f) << 24) |
		(int(genHash[offset+1]&0xff) << 16) |
		(int(genHash[offset+2]&0xff) << 8) |
		(int(genHash[offset+3] & 0xff))
	fmt.Printf("maskedOTPBinary: %x\n", maskedOTPBinary)

	// 4.
	otpValue := maskedOTPBinary % int(math.Pow10(passwordLen))
	fmt.Printf("got: %0*d\n", 10, otpValue)

	// Do this to rerun the test without cache
	assert.Equal(t, 1, 2)
}
