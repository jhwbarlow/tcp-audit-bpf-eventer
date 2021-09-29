package main

import bpf "github.com/aquasecurity/libbpfgo"

// BPFModule is an interface which describes objects which represent a BPF object
// containing one or more BPF programs which can be loaded into the kernel.
// Once loaded into the kernel, individual programs can be retrieved from the module
// and attached to BPF hooks within the kernel.
// The BPF object my also contain one or more BPF perf buffer maps, which can be
// initialised using the module.
type bpfModule interface {
	loadObject() error
	getProgram(name string) (bpfProgram, error)
	initPerfBuf(name string,
		eventsChan chan []byte,
		droppedEventCountChan chan uint64,
		sizeInPages int) (bpfPerfBuffer, error)
	close()
}

// LibBPFGoBPFModule is a wrapper around a libbpfgo Module, allowing it to
// return interfaces instead of concrete types to enable mocking.
type libBPFGoBPFModule struct {
	module *bpf.Module
}

func newLibBPFGoBPFModule(module *bpf.Module) *libBPFGoBPFModule {
	return &libBPFGoBPFModule{module}
}

// LoadObject loads the BPF object represented by this module into the kernel.
func (m *libBPFGoBPFModule) loadObject() error {
	return m.module.BPFLoadObject()
}

// GetProgram returns a BPFProgram representing an individual BPF program within
// the loaded module.
func (m *libBPFGoBPFModule) getProgram(name string) (bpfProgram, error) {
	program, err := m.module.GetProgram(name)
	if err != nil {
		return nil, err
	}

	return newLibBPFGoBPFProgram(program), nil
}

// InitPerfBuf initialises the named perf buffer within the loaded module.
// Once loaded, events and/or dropped event counts will be delivered on the channels
// provided in eventsChan and droppedEventCountChan, respectively.
// The size (in memory pages) of the map within the kernel is given by sizeInPages.
func (m *libBPFGoBPFModule) initPerfBuf(name string,
	eventsChan chan []byte,
	droppedEventCountChan chan uint64,
	sizeInPages int) (bpfPerfBuffer, error) {
	return m.module.InitPerfBuf(name, eventsChan, droppedEventCountChan, sizeInPages)
}

// Close detaches and unloads all items in the kernel related to this module, including
// programs and perf buffers.
func (m *libBPFGoBPFModule) close() {
	m.module.Close()
}
