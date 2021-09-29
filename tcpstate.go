package main

import (
	"fmt"

	"github.com/jhwbarlow/tcp-audit-common/pkg/tcpstate"
)

// Kernel TCP states defined in kernel (net/tcp_states.h)
const (
	TCPEstablished = iota + 1
	TCPSynSent
	TCPSynRecv
	TCPFinWait1
	TCPFinWait2
	TCPTimeWait
	TCPClose
	TCPCloseWait
	TCPLastAck
	TCPListen
	TCPClosing
	TCPNewSynRecv
)

func convertState(kernelState int32) (tcpstate.State, error) {
	switch kernelState {
	case TCPEstablished:
		return tcpstate.StateEstablished, nil
	case TCPSynSent:
		return tcpstate.StateSynSent, nil
	case TCPSynRecv:
		return tcpstate.StateSynReceived, nil
	case TCPFinWait1:
		return tcpstate.StateFinWait1, nil
	case TCPFinWait2:
		return tcpstate.StateFinWait2, nil
	case TCPTimeWait:
		return tcpstate.StateTimeWait, nil
	case TCPClose:
		return tcpstate.StateClosed, nil
	case TCPCloseWait:
		return tcpstate.StateCloseWait, nil
	case TCPLastAck:
		return tcpstate.StateLastAck, nil
	case TCPListen:
		return tcpstate.StateListen, nil
	case TCPClosing:
		return tcpstate.StateClosing, nil
	case TCPNewSynRecv:
		return tcpstate.StateSynReceived, nil
	default:
		return tcpstate.State(""), fmt.Errorf("illegal kernel TCP state: %d", kernelState)
	}
}
