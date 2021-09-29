package main

import (
	"testing"

	"github.com/jhwbarlow/tcp-audit-common/pkg/tcpstate"
)

func TestConvertTCPState(t *testing.T) {
	tests := [...]struct {
		input    int32
		expected tcpstate.State
	}{
		{TCPEstablished, tcpstate.StateEstablished},
		{TCPSynSent, tcpstate.StateSynSent},
		{TCPSynRecv, tcpstate.StateSynReceived},
		{TCPFinWait1, tcpstate.StateFinWait1},
		{TCPFinWait2, tcpstate.StateFinWait2},
		{TCPTimeWait, tcpstate.StateTimeWait},
		{TCPClose, tcpstate.StateClosed},
		{TCPCloseWait, tcpstate.StateCloseWait},
		{TCPLastAck, tcpstate.StateLastAck},
		{TCPListen, tcpstate.StateListen},
		{TCPClosing, tcpstate.StateClosing},
		{TCPNewSynRecv, tcpstate.StateSynReceived},
	}

	for _, test := range tests {
		output, err := convertState(test.input)
		if err != nil {
			t.Errorf("expected nil error, got %v (of type %T) for TCP state %d", err, err, test.input)
		}

		if output != test.expected {
			t.Errorf("input %d: expected output %q, got %q", test.input, test.expected, output)
		}
	}
}

func TestConvertIllegalTCPStateError(t *testing.T) {
	_, err := convertState(0xBAD)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}
