package main

import (
	"fmt"
	"log"
)

// Must match that used in the BPF C
const (
	tcpStateChangePerfBufName    = "events"
	tcpStateChangeTracepointName = "sock:inet_sock_set_state"
	tcpStateChangeBPFProgramName = "tracepoint__sock_inet_sock_set_state"
)

// BPFRunner is an interface which describes objects which load a BPF program
// into the kernel and then sends the resultant TCP-state events on the
// returned channel. If the kernel buffer is full and the BPF program has to
// drop events, the number of dropped events is sent on the droppedEventCountChan
// channel.
type bpfRunner interface {
	run() error
	eventChannel() <-chan []byte
	droppedEventCountChannel() <-chan uint64
	close() error
}

// LibBPFGoBPFRunner is a BPFRunner which loads a BPF program into the kernel using
// the libbbfgo library.
type libBPFGoBPFRunner struct {
	tcpStateChangeEventChannelSize      int
	droppedEventsChannelSize            int
	tcpStateChangeEventPerfBufSizePages int
	bpfModuleCreator                    bpfModuleCreator

	module                bpfModule
	eventChan             <-chan []byte
	droppedEventCountChan <-chan uint64
}

func newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize int,
	droppedEventsChannelSize int,
	tcpStateChangeEventPerfBufSizePages int,
	bpfModuleCreator bpfModuleCreator) *libBPFGoBPFRunner {
	return &libBPFGoBPFRunner{
		tcpStateChangeEventChannelSize:      tcpStateChangeEventChannelSize,
		droppedEventsChannelSize:            droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages: tcpStateChangeEventPerfBufSizePages,
		bpfModuleCreator:                    bpfModuleCreator,
	}
}

// Run loads a BPF program into the kernel and attaches it to the appropriate kernel
// tracepoint in order to create TCP state-change events.
func (r *libBPFGoBPFRunner) run() error {
	module, err := r.bpfModuleCreator.createModule("tcp-audit")
	if err != nil {
		return fmt.Errorf("creating BPF module: %w", err)
	}
	r.module = module

	if err := module.loadObject(); err != nil {
		return fmt.Errorf("loading BPF object into kernel: %w", err)
	}

	program, err := module.getProgram(tcpStateChangeBPFProgramName)
	if err != nil {
		return fmt.Errorf("loading BPF program: %w", err)
	}

	if err = program.attachTracepoint(tcpStateChangeTracepointName); err != nil {
		return fmt.Errorf("attaching to tracepoint: %w", err)
	}

	eventChan := make(chan []byte, r.tcpStateChangeEventChannelSize)
	droppedEventCountChan := make(chan uint64, r.droppedEventsChannelSize)

	buf, err := module.initPerfBuf(tcpStateChangePerfBufName,
		eventChan,
		droppedEventCountChan,
		r.tcpStateChangeEventPerfBufSizePages)
	if err != nil {
		return fmt.Errorf("initialising perf buffer: %w", err)
	}
	r.eventChan = eventChan
	r.droppedEventCountChan = droppedEventCountChan
	buf.Start()

	return nil
}

func (r *libBPFGoBPFRunner) eventChannel() <-chan []byte {
	return r.eventChan
}

func (r *libBPFGoBPFRunner) droppedEventCountChannel() <-chan uint64 {
	return r.droppedEventCountChan
}

// Close unloads the BPF program loaded into the kernel by this runner.
// After this, no more TCP state-change events will be emitted on to the
// channels returned by the runner.
func (r *libBPFGoBPFRunner) close() error {
	log.Printf("Closing BPF module")
	r.module.close()

	return nil
}
