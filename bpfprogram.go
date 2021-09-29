package main

import bpf "github.com/aquasecurity/libbpfgo"

// BPFProgram is an interface which describes objects representing BPF programs.
type bpfProgram interface {
	attachTracepoint(tracepoint string) error
}

// LibBPFGoBPFProgram is a wrapper around a libbpfgo BPFProgram,
// allowing the API to simplified to simplify mocking.
type libBPFGoBPFProgram struct {
	program *bpf.BPFProg
}

func newLibBPFGoBPFProgram(program *bpf.BPFProg) *libBPFGoBPFProgram {
	return &libBPFGoBPFProgram{program}
}

// AttachTracepoint attaches this program to the provided kernel tracepoint.
// The tracepoint should be supplied in format `subsystem:tracepoint`.
func (p *libBPFGoBPFProgram) attachTracepoint(tracepoint string) error {
	_, err := p.program.AttachTracepoint(tracepoint)
	return err
}
