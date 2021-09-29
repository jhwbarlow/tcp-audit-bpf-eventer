package main

import (
	"encoding/binary"
	"unsafe"
)

func systemEndianess() binary.ByteOrder {
	test := uint16(0xF00D)
	testByte := *((*byte)(unsafe.Pointer(&test)))

	if testByte == 0xF0 {
		return binary.BigEndian
	}

	return binary.LittleEndian
}
