package main

import "log"

// DroppedEventHandler is an interface which describes objects which
// handle dropped events (events which the kernel could not write to
// the kernel BPF perf buffer due to it being full).
type droppedEventHandler interface {
	handle(droppedEventsCount uint64) error
}

// LoggingDroppedEventHandler logs an dropped event message to stderr.
type loggingDroppedEventHandler struct{}

// Handle handles a dropped event by logging a message to stderr.
func (*loggingDroppedEventHandler) handle(droppedEventsCount uint64) error {
	// There is nothing we can do about a dropped event,
	// except perhaps increase the buffer size or poll the
	// perf buffer more quickly, so just log it.
	log.Printf("Dropped events occurred: %d", droppedEventsCount)
	return nil
}
