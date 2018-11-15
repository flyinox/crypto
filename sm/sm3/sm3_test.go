// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// sm3 hash algorithm.

package sm3

import (
	"fmt"
	"testing"
)

type sm3Test struct {
	out string
	in  string
}

var golden = []sm3Test{
	{"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b", ""},
	{"00607cd3ffb78125184758bb06d23757beb3d57be9447b1bb58a6a6e67752313", "616263"},
	{"623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88", "a"},
	{"2bb6c53ad20eaf2552425f44e72d96d1b61e63310a1a30f4e5406a103619177d", "He who has a shady past knows that nice guys finish last."},
	{"5ecec640017afd77d00147ef42fdb8e7901f089a62c1888637917e89bb3a6532", "I wouldn't marry him with a ten foot pole."},
	{"26598310dfeea2787829ec21d88fbf9f17c9299adf23de49cfcf26030dbc0e35", "Free! Free!/A trip/to Mars/for 900/empty jars/Burma Shave"},
	{"c3555aaf32465c61f681e6dabcc0c95ac93e7c383b1c6eeb621a5ca0eb300508", "The days of the digital watch are numbered.  -Tom Stoppard"},
}

func TestGolden(t *testing.T) {
	for i := 0; i < len(golden); i++ {
		g := golden[i]
		s := fmt.Sprintf("%x", SumSM3([]byte(g.in)))
		if s != g.out {
			t.Fatalf("SumSM3 function: SM3(%s) = %s want %s", g.in, s, g.out)
		}
	}
}

func TestPnPanic(t *testing.T) {
		var buf = make([]byte, 4000)

		SumSM3(buf)
}


func TestSize(t *testing.T) {
	c := New()
	if got := c.Size(); got != Size {
		t.Errorf("Size = %d; want %d", got, Size)
	}
}

func TestBlockSize(t *testing.T) {
	c := New()
	if got := c.BlockSize(); got != BlockSize {
		t.Errorf("BlockSize = %d want %d", got, BlockSize)
	}
}

var bench = New()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
