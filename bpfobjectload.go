package main

import (
	_ "embed"
	"errors"
)

var errNoBPFObject error = errors.New("no BPF object available")

// BPFObjectLoader is an interface which describes objects which
// return/"load" a BPF ELF-format object as a byte slice.
type bpfObjectLoader interface {
	load() ([]byte, error)
}

//go:embed bpf.o
var bpfObj []byte

// EmbeddedBPFObjectLoader returns a BPF ELF-format object as a
// byte slice, the object having been embedded in the Go executable
// at build-time.
type embeddedBPFObjectLoader struct{}

// Load returns a BPF ELF-format object.
func (*embeddedBPFObjectLoader) load() ([]byte, error) {
	// Guard against some build-time mishap
	if bpfObj == nil || len(bpfObj) == 0 {
		return nil, errNoBPFObject
	}

	return bpfObj, nil
}
