package main

const taskCommLen = 16 // Defined in kernel (linux/sched.h)

// RawEvent is the event received from the kernel via a BPF perf buffer.
// The struct layout must match that of the equivalent struct in the BPF C.
type rawEvent struct {
	CommOnCPU            [taskCommLen]byte
	SocketMemAddr        uint64
	PIDOnCPU             uint32
	SocketINode          uint32
	SocketUID, SocketGID uint32
	OldState, NewState   int32
	SrcPort, DstPort     uint16
	SrcAddr, DstAddr     [4]uint8
	SockState            uint8
}
