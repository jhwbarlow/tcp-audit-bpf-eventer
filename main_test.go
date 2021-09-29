package main

import (
	"errors"
	"testing"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
)

type mockBPFRunner struct {
	eventChannelToReturn             <-chan []byte
	droppedEventCountChannelToReturn <-chan uint64

	runErrorToReturn   error
	closeErrorToReturn error

	runCalled                      bool
	eventChannelCalled             bool
	droppedEventCountChannelCalled bool
	closeCalled                    bool
}

func newMockBPFRunner(eventChannelToReturn <-chan []byte,
	droppedEventCountChannelToReturn <-chan uint64,
	runErrorToReturn error,
	closeErrorToReturn error) *mockBPFRunner {
	return &mockBPFRunner{
		eventChannelToReturn:             eventChannelToReturn,
		droppedEventCountChannelToReturn: droppedEventCountChannelToReturn,
		runErrorToReturn:                 runErrorToReturn,
		closeErrorToReturn:               closeErrorToReturn,
	}
}

func (mr *mockBPFRunner) run() error {
	mr.runCalled = true

	if mr.runErrorToReturn != nil {
		return mr.runErrorToReturn
	}

	return nil
}

func (mr *mockBPFRunner) eventChannel() <-chan []byte {
	mr.eventChannelCalled = true

	return mr.eventChannelToReturn
}

func (mr *mockBPFRunner) droppedEventCountChannel() <-chan uint64 {
	mr.droppedEventCountChannelCalled = true

	return mr.droppedEventCountChannelToReturn
}

func (mr *mockBPFRunner) close() error {
	mr.closeCalled = true

	if mr.closeErrorToReturn != nil {
		return mr.closeErrorToReturn
	}

	return nil
}

type mockDroppedEventHandler struct {
	errorToReturn       error
	chanToCloseOnHandle chan<- struct{}

	handleCalled bool
}

func newMockDroppedEventHandler(errorToReturn error,
	chanToCloseOnHandle chan<- struct{}) *mockDroppedEventHandler {
	return &mockDroppedEventHandler{
		errorToReturn:       errorToReturn,
		chanToCloseOnHandle: chanToCloseOnHandle,
	}
}

func (mh *mockDroppedEventHandler) handle(droppedEventsCount uint64) error {
	mh.handleCalled = true

	if mh.chanToCloseOnHandle != nil {
		close(mh.chanToCloseOnHandle)
	}

	if mh.errorToReturn != nil {
		return mh.errorToReturn
	}

	return nil
}

type mockDeserialiser struct {
	eventToReturn *event.Event

	errorToReturn error

	toEventCalled bool
}

func newMockDeserialiser(eventToReturn *event.Event, errorToReturn error) *mockDeserialiser {
	return &mockDeserialiser{
		eventToReturn: eventToReturn,
		errorToReturn: errorToReturn,
	}
}

func (md *mockDeserialiser) toEvent(data []byte) (*event.Event, error) {
	md.toEventCalled = true

	if md.errorToReturn != nil {
		return nil, md.errorToReturn
	}

	return md.eventToReturn, nil
}

func TestReadEvent(t *testing.T) {
	mockEvent := &event.Event{}
	mockDeserialiser := newMockDeserialiser(mockEvent, nil)
	mockEventChannel := make(chan []byte, 1)     // This will be unused as the real deserialiser is mocked and does not consume the []byte read from this channel
	var mockDroppedEventCountChannel chan uint64 // Nil so it will not be selected
	mockBPFRunner := newMockBPFRunner(mockEventChannel, mockDroppedEventCountChannel, nil, nil)
	mockDroppedEventHandler := newMockDroppedEventHandler(nil, nil)

	eventer, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err != nil {
		t.Errorf("expected nil constructor error, got %v (of type %T)", err, err)
	}

	mockEventChannel <- []byte{} // Dummy event data to force selection on the channel

	event, err := eventer.Event()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !event.Equal(mockEvent) {
		t.Error("expected returned event to be equal to mock event, but was not")
	}

	if !mockBPFRunner.eventChannelCalled {
		t.Error("expected BPF runner to be called, but was not")
	}

	if !mockDeserialiser.toEventCalled {
		t.Error("expected deserialiser retriever to be called, but was not")
	}

	err = eventer.Close()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !mockBPFRunner.closeCalled {
		t.Error("expected BPF runner to be closed, but was not")
	}

	// Further attempts to read an event should return a "already closed" error
	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, ErrEventerClosed) {
		t.Errorf("expected error chain to include %q, but did not", ErrEventerClosed)
	}
}

func TestReadDroppedEventCount(t *testing.T) {
	mockEvent := &event.Event{}
	mockDeserialiser := newMockDeserialiser(mockEvent, nil)
	mockEventChannel := make(chan []byte) // This will be unused as the real deserialiser is mocked and does not consume the []byte read from this channel
	mockDroppedEventCountChannel := make(chan uint64)
	mockBPFRunner := newMockBPFRunner(mockEventChannel, mockDroppedEventCountChannel, nil, nil)
	chanToCloseOnDroppedEventHandle := make(chan struct{})
	mockDroppedEventHandler := newMockDroppedEventHandler(nil, chanToCloseOnDroppedEventHandle)
	mockDroppedEventCount := uint64(10)

	eventer, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err != nil {
		t.Errorf("expected nil constructor error, got %v (of type %T)", err, err)
	}

	// eventer.Event() is a blocking call. We must run it in its own goroutine so we can
	// control the flow using channels in the current goroutine
	errChan := make(chan error)
	go func(chan<- error) {
		_, err = eventer.Event()
		errChan <- err
		close(errChan)
	}(errChan)

	mockDroppedEventCountChannel <- mockDroppedEventCount // Ensure this is sent first to ensure it is read from the channel
	<-chanToCloseOnDroppedEventHandle                     // Ensure dropped event count has been processed before continuing
	mockEventChannel <- []byte{}                          // Dummy event data to force selection on the channel and the eventer to return

	err = <-errChan
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !mockDroppedEventHandler.handleCalled {
		t.Error("expected dropped event handler to be called, but was not")
	}
}

func TestReadEventDeserialiserError(t *testing.T) {
	mockError := errors.New("mock deserialiser error")
	mockDeserialiser := newMockDeserialiser(nil, mockError)
	mockEventChannel := make(chan []byte, 1)     // This will be unused as the real deserialiser is mocked and does not consume the []byte read from this channel
	var mockDroppedEventCountChannel chan uint64 // Nil so it will not be selected
	mockBPFRunner := newMockBPFRunner(mockEventChannel, mockDroppedEventCountChannel, nil, nil)
	mockDroppedEventHandler := newMockDroppedEventHandler(nil, nil)

	eventer, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err != nil {
		t.Errorf("expected nil constructor error, got %v (of type %T)", err, err)
	}

	mockEventChannel <- []byte{} // Dummy event data to force selection on the channel

	_, err = eventer.Event()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}

func TestReadDroppedEventCountHandlerError(t *testing.T) {
	mockEvent := &event.Event{}
	mockDeserialiser := newMockDeserialiser(mockEvent, nil)
	mockEventChannel := make(chan []byte) // This will be unused as the real deserialiser is mocked and does not consume the []byte read from this channel
	mockDroppedEventCountChannel := make(chan uint64)
	mockBPFRunner := newMockBPFRunner(mockEventChannel, mockDroppedEventCountChannel, nil, nil)
	chanToCloseOnDroppedEventHandle := make(chan struct{})
	mockError := errors.New("mock dropped event count handler error")
	mockDroppedEventHandler := newMockDroppedEventHandler(mockError, chanToCloseOnDroppedEventHandle)
	mockDroppedEventCount := uint64(10)

	eventer, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err != nil {
		t.Errorf("expected nil constructor error, got %v (of type %T)", err, err)
	}

	// eventer.Event() is a blocking call. We must run it in its own goroutine so we can
	// control the flow using channels in the current goroutine
	errChan := make(chan error)
	go func(chan<- error) {
		_, err = eventer.Event()
		errChan <- err
		close(errChan)
	}(errChan)

	mockDroppedEventCountChannel <- mockDroppedEventCount // Ensure this is sent first to ensure it is read from the channel
	<-chanToCloseOnDroppedEventHandle                     // Ensure dropped event count has been processed before continuing
	mockEventChannel <- []byte{}                          // Dummy event data to force selection on the channel and the eventer to return

	// Despite the dropped event handler returning an error, the eventer should continue and
	// return the next non-dropped event successfully
	err = <-errChan
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !mockDroppedEventHandler.handleCalled {
		t.Error("expected dropped event handler to be called, but was not")
	}

	err = eventer.Close()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}
}

func TestEventerConstructorBPFRunnerError(t *testing.T) {
	mockEvent := &event.Event{}
	mockDeserialiser := newMockDeserialiser(mockEvent, nil)
	mockError := errors.New("mock BPF runner run error")
	mockBPFRunner := newMockBPFRunner(nil, nil, mockError, nil)
	mockDroppedEventHandler := newMockDroppedEventHandler(nil, nil)

	_, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err == nil {
		t.Error("expected constructor error, got nil")
	}

	t.Logf("got constructor error %q (of type %T)", err, err)
}

func TestEventerCloseError(t *testing.T) {
	mockDeserialiser := newMockDeserialiser(nil, nil)
	mockError := errors.New("mock BPF runner close error")
	mockBPFRunner := newMockBPFRunner(nil, nil, nil, mockError)
	mockDroppedEventHandler := newMockDroppedEventHandler(nil, nil)

	eventer, err := newEventer(mockDeserialiser, mockBPFRunner, mockDroppedEventHandler)
	if err != nil {
		t.Errorf("expected nil constructor error, got %v (of type %T)", err, err)
	}

	err = eventer.Close()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !mockBPFRunner.closeCalled {
		t.Error("expected BPF runner to be closed, but was not")
	}
}
