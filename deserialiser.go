package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"time"
	"unsafe"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
	"github.com/jhwbarlow/tcp-audit-common/pkg/socketstate"

	"C"
)

// Deserialiser is an interface which describes objects which convert a byte
// slice containing a TCP state-change event into an event object.
type deserialiser interface {
	toEvent(data []byte) (*event.Event, error)
}

// CStructDeserialiser converts a byte slice containing a C-struct representing
// a BPF TCP state-change event into a TCP state-change event.
type cStructDeserialiser struct {
	endianess binary.ByteOrder
}

func newCStructDeserialiser(endianess binary.ByteOrder) *cStructDeserialiser {
	return &cStructDeserialiser{endianess}
}

// ToEvent creates a TCP state-change event object from the supplied byte
// slice containing the C-struct data.
func (d *cStructDeserialiser) toEvent(eventData []byte) (*event.Event, error) {
	time := time.Now().UTC()

	rawEvent := new(rawEvent)
	if err := binary.Read(bytes.NewBuffer(eventData), d.endianess, rawEvent); err != nil {
		return nil, fmt.Errorf("decoding event data: %w", err)
	}

	oldState, err := convertState(rawEvent.OldState)
	if err != nil {
		return nil, fmt.Errorf("converting kernel old TCP state: %w", err)
	}

	newState, err := convertState(rawEvent.NewState)
	if err != nil {
		return nil, fmt.Errorf("converting kernel new TCP state: %w", err)
	}

	socketState, err := socketstate.FromInt(rawEvent.SockState)
	if err != nil {
		return nil, fmt.Errorf("converting socket state: %w", err)
	}

	socketInfo := &event.SocketInfo{
		ID:          strconv.FormatUint(rawEvent.SocketMemAddr, 16),
		INode:       rawEvent.SocketINode,
		UID:         rawEvent.SocketUID,
		GID:         rawEvent.SocketGID,
		SocketState: socketState,
	}

	event := &event.Event{
		Time:         time,
		PIDOnCPU:     int(rawEvent.PIDOnCPU),
		CommandOnCPU: C.GoString((*C.char)(unsafe.Pointer(&rawEvent.CommOnCPU))),
		SourceIP:     net.IP(rawEvent.SrcAddr[:]),
		DestIP:       net.IP(rawEvent.DstAddr[:]),
		SourcePort:   rawEvent.SrcPort,
		DestPort:     rawEvent.DstPort,
		OldState:     oldState,
		NewState:     newState,
		SocketInfo:   socketInfo,
	}

	return event, nil
}
