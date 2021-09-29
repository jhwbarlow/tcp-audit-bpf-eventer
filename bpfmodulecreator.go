package main

import (
	"fmt"

	bpf "github.com/aquasecurity/libbpfgo"
)

// BPFModuleCreator is an interface which describes objects which are "factories"
// for BPFModules.
type bpfModuleCreator interface {
	createModule(name string) (bpfModule, error)
}

// LibBPFGoBPFModuleCreator creates a BPFModule using BPF object data provided by
// a BPFObjectLoader supplied during construction. It leans on the libbpfgo
// package to perform the "heavy lifting".
type libBPFGoBPFModuleCreator struct {
	bpfObjectLoader bpfObjectLoader
}

func newLibBPFGoBPFModuleCreator(bpfObjectLoader bpfObjectLoader) *libBPFGoBPFModuleCreator {
	return &libBPFGoBPFModuleCreator{bpfObjectLoader}
}

// CreateModule creates a new BPFModule using the BPFObjectLoader supplied during
// construction to obtain the BPF object from which to create the BPFModule.
// The name of the module as provided to the kernel is given in the name parameter.
func (c *libBPFGoBPFModuleCreator) createModule(name string) (bpfModule, error) {
	bpfObj, err := c.bpfObjectLoader.load()
	if err != nil {
		return nil, fmt.Errorf("loading BPF object: %w", err)
	}

	module, err := bpf.NewModuleFromBuffer(bpfObj, name)
	if err != nil {
		return nil, err
	}

	return newLibBPFGoBPFModule(module), nil
}
