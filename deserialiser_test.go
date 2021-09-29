package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
	"github.com/jhwbarlow/tcp-audit-common/pkg/socketstate"
	"github.com/jhwbarlow/tcp-audit-common/pkg/tcpstate"
)

func TestDeserialiseToEvent(t *testing.T) {
	timeNow := time.Now().UTC()
	mockEvent := &event.Event{
		Time:         timeNow,
		PIDOnCPU:     252075,
		CommandOnCPU: "postgres",
		SourceIP:     net.ParseIP("172.17.0.2"),
		DestIP:       net.ParseIP("172.17.0.3"),
		SourcePort:   5432,
		DestPort:     55420,
		OldState:     tcpstate.StateLastAck,
		NewState:     tcpstate.StateClosed,
		SocketInfo: &event.SocketInfo{
			ID:          "ffff9e45710b6900",
			INode:       0,
			UID:         0,
			GID:         0,
			SocketState: socketstate.StateFree,
		},
	}

	/*
			char comm_on_cpu[TASK_COMM_LEN];
		__u64 sock_addr;
		__u32 pid_on_cpu;
		__u32 sock_inode;
		__u32 sock_uid;
		__u32 sock_gid;
		__s32 old_state;
		__s32 new_state;
		__u16 src_port;
		__u16 dst_port;
		__u8 src_addr[4];
		__u8 dst_addr[4];
		__u8 sock_state;
	*/
	mockEventData := []byte{
		0x70, 0x6F, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ASCII "postgres"
		0x00, 0x69, 0x0B, 0x71, 0x45, 0x9E, 0xFF, 0xFF, // 0xffff9e45710b6900 little endian
		0xAB, 0xD8, 0x03, 0x00, // 252075 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x09, 0x00, 0x00, 0x00, // 9 little endian (LAST-ACK)
		0x07, 0x00, 0x00, 0x00, // 7 little endian (CLOSED)
		0x38, 0x15, // 5432 little endian
		0x7C, 0xD8, // 55420 little endian
		0xAC, 0x11, 0x00, 0x02, // 172.17.0.2 big endian
		0xAC, 0x11, 0x00, 0x03, // 172.17.0.3 big endian
		0x00,                                     // 0 (FREE)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment padding
	}

	deserialiser := newCStructDeserialiser(binary.LittleEndian)

	event, err := deserialiser.toEvent(mockEventData)
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	t.Logf("got event %q", event)

	event.Time = timeNow // Reset deserialised event time so comparison is equal
	if !event.Equal(mockEvent) {
		t.Error("expected deserialised event to be equal to mock event, but was not")
	}
}

func TestDeserialiseToEventDecodeError(t *testing.T) {
	deserialiser := newCStructDeserialiser(binary.LittleEndian)

	_, err := deserialiser.toEvent([]byte{0x00})
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeserialiseToEventIllegalTCPOldStateError(t *testing.T) {
	/*
			char comm_on_cpu[TASK_COMM_LEN];
		__u64 sock_addr;
		__u32 pid_on_cpu;
		__u32 sock_inode;
		__u32 sock_uid;
		__u32 sock_gid;
		__s32 old_state;
		__s32 new_state;
		__u16 src_port;
		__u16 dst_port;
		__u8 src_addr[4];
		__u8 dst_addr[4];
		__u8 sock_state;
	*/
	mockEventData := []byte{
		0x70, 0x6F, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ASCII "postgres"
		0x00, 0x69, 0x0B, 0x71, 0x45, 0x9E, 0xFF, 0xFF, // 0xffff9e45710b6900 little endian
		0xAB, 0xD8, 0x03, 0x00, // 252075 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0xBA, 0xD0, 0xBA, 0xD0, // illegal value
		0x07, 0x00, 0x00, 0x00, // 7 little endian (CLOSED)
		0x38, 0x15, // 5432 little endian
		0x7C, 0xD8, // 55420 little endian
		0xAC, 0x11, 0x00, 0x02, // 172.17.0.2 big endian
		0xAC, 0x11, 0x00, 0x03, // 172.17.0.3 big endian
		0x00,                                     // 0 (FREE)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment padding
	}
	deserialiser := newCStructDeserialiser(binary.LittleEndian)

	_, err := deserialiser.toEvent(mockEventData)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeserialiseToEventIllegalTCPNewStateError(t *testing.T) {
	/*
			char comm_on_cpu[TASK_COMM_LEN];
		__u64 sock_addr;
		__u32 pid_on_cpu;
		__u32 sock_inode;
		__u32 sock_uid;
		__u32 sock_gid;
		__s32 old_state;
		__s32 new_state;
		__u16 src_port;
		__u16 dst_port;
		__u8 src_addr[4];
		__u8 dst_addr[4];
		__u8 sock_state;
	*/
	mockEventData := []byte{
		0x70, 0x6F, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ASCII "postgres"
		0x00, 0x69, 0x0B, 0x71, 0x45, 0x9E, 0xFF, 0xFF, // 0xffff9e45710b6900 little endian
		0xAB, 0xD8, 0x03, 0x00, // 252075 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x09, 0x00, 0x00, 0x00, // 9 little endian (LAST-ACK)
		0x0B, 0xAD, 0x0B, 0xAD, // illegal value
		0x38, 0x15, // 5432 little endian
		0x7C, 0xD8, // 55420 little endian
		0xAC, 0x11, 0x00, 0x02, // 172.17.0.2 big endian
		0xAC, 0x11, 0x00, 0x03, // 172.17.0.3 big endian
		0x00,                                     // 0 (FREE)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment padding
	}
	deserialiser := newCStructDeserialiser(binary.LittleEndian)

	_, err := deserialiser.toEvent(mockEventData)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestDeserialiseToEventIllegalSocketStateError(t *testing.T) {
	/*
			char comm_on_cpu[TASK_COMM_LEN];
		__u64 sock_addr;
		__u32 pid_on_cpu;
		__u32 sock_inode;
		__u32 sock_uid;
		__u32 sock_gid;
		__s32 old_state;
		__s32 new_state;
		__u16 src_port;
		__u16 dst_port;
		__u8 src_addr[4];
		__u8 dst_addr[4];
		__u8 sock_state;
	*/
	mockEventData := []byte{
		0x70, 0x6F, 0x73, 0x74, 0x67, 0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ASCII "postgres"
		0x00, 0x69, 0x0B, 0x71, 0x45, 0x9E, 0xFF, 0xFF, // 0xffff9e45710b6900 little endian
		0xAB, 0xD8, 0x03, 0x00, // 252075 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x00, 0x00, 0x00, 0x00, // 0 little endian
		0x09, 0x00, 0x00, 0x00, // 9 little endian (LAST-ACK)
		0x07, 0x00, 0x00, 0x00, // 7 little endian (CLOSED)
		0x38, 0x15, // 5432 little endian
		0x7C, 0xD8, // 55420 little endian
		0xAC, 0x11, 0x00, 0x02, // 172.17.0.2 big endian
		0xAC, 0x11, 0x00, 0x03, // 172.17.0.3 big endian
		0xFF,                                     // illegal value
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Alignment padding
	}
	deserialiser := newCStructDeserialiser(binary.LittleEndian)

	_, err := deserialiser.toEvent(mockEventData)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}
