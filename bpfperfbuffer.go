package main

// BPFPerfBuffer is an interface which describes BPF perf buffer maps.
type bpfPerfBuffer interface {
	Start()
}
