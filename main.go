package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
)

// Magic, potentially tunable, constants
const (
	tcpStateChangeEventChannelSize      = 1024
	droppedEventsChannelSize            = 64
	tcpStateChangeEventPerfBufSizePages = 16 // Number copied from existing libbpf tools
)

var ErrEventerClosed = errors.New("read from closed eventer")

type Eventer struct {
	deserialiser        deserialiser
	droppedEventHandler droppedEventHandler
	bpfRunner           bpfRunner

	done chan struct{}
}

func New() (e event.Eventer, err error) {
	deserialiser := newCStructDeserialiser(systemEndianess())
	droppedEventHandler := new(loggingDroppedEventHandler)
	bpfObjectLoader := new(embeddedBPFObjectLoader)
	bpfModuleCreator := newLibBPFGoBPFModuleCreator(bpfObjectLoader)
	bpfRunner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		bpfModuleCreator)

	return newEventer(deserialiser, bpfRunner, droppedEventHandler)
}

func newEventer(deserialiser deserialiser,
	bpfRunner bpfRunner,
	droppedEventHandler droppedEventHandler) (*Eventer, error) {
	if err := bpfRunner.run(); err != nil {
		return nil, fmt.Errorf("loading BPF: %w", err)
	}

	return &Eventer{
		deserialiser:        deserialiser,
		bpfRunner:           bpfRunner,
		droppedEventHandler: droppedEventHandler,

		done: make(chan struct{}), // Closing this channel will cause Event() to no longer attempt to read from the BPF perf buffer
	}, nil
}

func (e *Eventer) Event() (*event.Event, error) {
	for {
		select {
		case <-e.done:
			return nil, ErrEventerClosed
		default:
		}

		select {
		case <-e.done:
			return nil, ErrEventerClosed
		case eventData, ok := <-e.bpfRunner.eventChannel():
			if !ok { // Check if the channel was closed, as the bpfRunner could be closed by Close() while Event() is being called
				return nil, ErrEventerClosed
			}

			event, err := e.deserialiser.toEvent(eventData)
			if err != nil {
				return nil, fmt.Errorf("deserialising event: %w", err)
			}

			return event, nil
		case droppedEventsCount, ok := <-e.bpfRunner.droppedEventCountChannel():
			if !ok {
				return nil, ErrEventerClosed
			}

			if err := e.droppedEventHandler.handle(droppedEventsCount); err != nil {
				// Don't return anything, just go around the loop again to find a non-dropped event.
				log.Printf("Error handling dropped event: %v", err)
			}
		}
	}
}

func (e *Eventer) Close() error {
	close(e.done) // Closing this channel will cause Event() to return ErrEventerClosed

	if err := e.bpfRunner.close(); err != nil {
		return fmt.Errorf("closing BPF runner: %w", err)
	}

	return nil
}
