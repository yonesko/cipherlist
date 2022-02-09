package cipherlist

import (
	"fmt"
	"testing"
)

func Test_Integration(t *testing.T) {
	ciphers, err := SupportedTLS12Ciphers("google.com")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(ciphers)
}
