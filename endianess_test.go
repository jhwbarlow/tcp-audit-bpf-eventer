package main

import (
	"encoding/binary"
	"runtime"
	"testing"
)

func TestSystemEndianess(t *testing.T) {
	endianess := systemEndianess()

	if runtime.GOARCH == "amd64" && endianess != binary.LittleEndian {
		t.Errorf("expected little endian on AMD64, got big endian")
	}
}
