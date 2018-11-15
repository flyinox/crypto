/*
// Copyright 2017 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package china crypto algorithm implements the sm2, sm3, sm4 algorithms
*/
package sm4

import (
	"bytes"
	"testing"
)

func TestEncAndDec(t *testing.T) {
	key := []byte("1234567890abcdef")
	msg := []byte("this is a test")
	encMsg := Sm4Ecb(key, msg, ENC)
	dec := Sm4Ecb(key, encMsg, DEC)
	if !bytes.Equal(msg, dec) {
		t.Errorf("sm4 self enc and dec failed")
	}
}

var buf = make([]byte, 8192)

func BenchmarkSm4Ecb(b *testing.B) {
	b.SetBytes(8)

}

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	key := []byte("1234567890abcdef")
	for i := 0; i < b.N; i++ {
		Sm4Ecb(key, buf[:size], ENC)
	}
}

func BenchmarkSm4Ecb8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkSm4Ecb1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkSm4Ecb8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
