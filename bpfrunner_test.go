package main

import (
	"bytes"
	"errors"
	"testing"
)

type mockBPFModuleCreator struct {
	errorToReturn     error
	bpfModuleToReturn bpfModule

	called bool
}

func newMockBPFModuleCreator(bpfModuleToReturn bpfModule, errorToReturn error) *mockBPFModuleCreator {
	return &mockBPFModuleCreator{
		bpfModuleToReturn: bpfModuleToReturn,
		errorToReturn:     errorToReturn,
	}
}

func (mc *mockBPFModuleCreator) createModule(name string) (bpfModule, error) {
	mc.called = true

	if mc.errorToReturn != nil {
		return nil, mc.errorToReturn
	}

	return mc.bpfModuleToReturn, nil
}

type mockBPFModule struct {
	programToReturn bpfProgram
	perfBufToReturn bpfPerfBuffer

	bpfLoadObjectErrorToReturn error
	getProgramErrorToReturn    error
	initPerfBufErrorToReturn   error

	bpfLoadObjectCalled bool
	getProgramCalled    bool
	initPerfBufCalled   bool
	closeCalled         bool

	receivedProgramName           string
	receivedPerfBufferName        string
	receivedEventChan             chan []byte
	receivedDroppedEventCountChan chan uint64
}

func newMockBPFModule(programToReturn bpfProgram,
	perfBufToReturn bpfPerfBuffer,
	bpfLoadObjectErrorToReturn error,
	getProgramErrorToReturn error,
	initPerfBufErrorToReturn error) *mockBPFModule {
	return &mockBPFModule{
		programToReturn:            programToReturn,
		perfBufToReturn:            perfBufToReturn,
		bpfLoadObjectErrorToReturn: bpfLoadObjectErrorToReturn,
		getProgramErrorToReturn:    getProgramErrorToReturn,
		initPerfBufErrorToReturn:   initPerfBufErrorToReturn,
	}
}

func (mm *mockBPFModule) loadObject() error {
	mm.bpfLoadObjectCalled = true

	if mm.bpfLoadObjectErrorToReturn != nil {
		return mm.bpfLoadObjectErrorToReturn
	}

	return nil
}

func (mm *mockBPFModule) getProgram(name string) (bpfProgram, error) {
	mm.getProgramCalled = true
	mm.receivedProgramName = name

	if mm.getProgramErrorToReturn != nil {
		return nil, mm.getProgramErrorToReturn
	}

	return mm.programToReturn, nil
}

func (mm *mockBPFModule) initPerfBuf(name string,
	eventsChan chan []byte,
	lostChan chan uint64,
	pageCnt int) (bpfPerfBuffer, error) {
	mm.initPerfBufCalled = true
	mm.receivedPerfBufferName = name
	mm.receivedEventChan = eventsChan
	mm.receivedDroppedEventCountChan = lostChan

	if mm.initPerfBufErrorToReturn != nil {
		return nil, mm.initPerfBufErrorToReturn
	}

	return mm.perfBufToReturn, nil
}

func (mm *mockBPFModule) close() {
	mm.closeCalled = true
}

type mockBPFProgram struct {
	errorToReturn error

	attachTracepointCalled bool
	receivedTracepointName string
}

func newMockBPFProgram(errorToReturn error) *mockBPFProgram {
	return &mockBPFProgram{errorToReturn: errorToReturn}
}

func (mp *mockBPFProgram) attachTracepoint(tracepoint string) error {
	mp.attachTracepointCalled = true
	mp.receivedTracepointName = tracepoint

	if mp.errorToReturn != nil {
		return mp.errorToReturn
	}

	return nil
}

type mockBPFPerfBuffer struct {
	called bool
}

func newMockBPFPerfBuffer() *mockBPFPerfBuffer {
	return new(mockBPFPerfBuffer)
}

func (mb *mockBPFPerfBuffer) Start() {
	mb.called = true
}

func TestBPFRunner(t *testing.T) {
	mockProgram := newMockBPFProgram(nil)
	mockPerfBuffer := newMockBPFPerfBuffer()
	mockModule := newMockBPFModule(mockProgram, mockPerfBuffer, nil, nil, nil)
	mockBPFModuleCreator := newMockBPFModuleCreator(mockModule, nil)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !mockModule.bpfLoadObjectCalled {
		t.Error("expected BPF module load object to be called, but was not")
	}

	if !mockModule.getProgramCalled {
		t.Error("expected BPF module get program to be called, but was not")
	}

	// Check program name is what we expect it to be (must match what is in the C)
	if mockModule.receivedProgramName != tcpStateChangeBPFProgramName {
		t.Errorf("expected BPF module to be requested to load program %q, but was %q",
			tcpStateChangeBPFProgramName,
			mockModule.receivedProgramName)
	}

	if !mockProgram.attachTracepointCalled {
		t.Error("expected tracepoint to be attached to BPF program, but was not")
	}

	// Check tracepoint name is what we expect it to be (must match what is in the kernel)
	if mockProgram.receivedTracepointName != tcpStateChangeTracepointName {
		t.Errorf("expected BPF program to be attached to tracepoint %q, but was %q",
			tcpStateChangeTracepointName,
			mockProgram.receivedTracepointName)
	}

	if !mockModule.initPerfBufCalled {
		t.Error("expected BPF module perf buffer to be initialised, but was not")
	}

	// Check perf buf name is what we expect it to be (must match what is in the C)
	if mockModule.receivedPerfBufferName != tcpStateChangePerfBufName {
		t.Errorf("expected BPF module to be requested to init perf buffer %q, but was %q",
			tcpStateChangePerfBufName,
			mockModule.receivedPerfBufferName)
	}

	if !mockPerfBuffer.called {
		t.Error("expected BPF perf buffer to be started, but was not")
	}

	// Check BPF module has an event channel set in it by the BPF runner.
	// This is the channel that the perf buffer would place events on in real life.
	if mockModule.receivedEventChan == nil {
		t.Error("expected BPF runner to set event channel in module, but did not")
	}

	// Check events channel delivers event data on the channel obtained from the BPF runner
	mockEventData := []byte{0xCA, 0xFE, 0xF0, 0x0D}
	go func() {
		mockModule.receivedEventChan <- mockEventData
	}()
	eventData := <-runner.eventChannel()

	if !bytes.Equal(eventData, mockEventData) {
		t.Errorf("expected BPF runner events channel to return %X, but returned %X",
			mockEventData,
			eventData)
	}

	// Check BPF module has a dropped event count channel set in it by the BPF runner.
	// This is the channel that the perf buffer would place drop counts on in real life.
	if mockModule.receivedDroppedEventCountChan == nil {
		t.Error("expected BPF runner to set dropped event count channel in module, but did not")
	}

	// Check dropped events channel delivers drop count on the channel obtained from the BPF runner
	var mockDroppedEventCount uint64 = 1
	go func() {
		mockModule.receivedDroppedEventCountChan <- mockDroppedEventCount
	}()
	droppedEventCount := <-runner.droppedEventCountChannel()

	if droppedEventCount != mockDroppedEventCount {
		t.Errorf("expected BPF runner dropped event count channel to return %d, but returned %d",
			mockDroppedEventCount,
			droppedEventCount)
	}

	err = runner.close()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}

	if !mockModule.closeCalled {
		t.Error("expected BPF module to be closed, but was not")
	}
}

func TestBPFRunnerModuleCreatorError(t *testing.T) {
	mockError := errors.New("mock BPF module creator error")
	mockBPFModuleCreator := newMockBPFModuleCreator(nil, mockError)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockBPFModuleCreator.called {
		t.Error("expected BPF module creator to be called, but was not")
	}
}

func TestBPFRunnerModuleLoadObjectError(t *testing.T) {
	mockError := errors.New("mock BPF module load error")
	mockModule := newMockBPFModule(nil, nil, mockError, nil, nil)
	mockBPFModuleCreator := newMockBPFModuleCreator(mockModule, nil)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockModule.bpfLoadObjectCalled {
		t.Error("expected BPF module load object to be called, but was not")
	}
}

func TestBPFRunnerModuleGetProgramError(t *testing.T) {
	mockError := errors.New("mock BPF get program error")
	mockModule := newMockBPFModule(nil, nil, nil, mockError, nil)
	mockBPFModuleCreator := newMockBPFModuleCreator(mockModule, nil)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockModule.getProgramCalled {
		t.Error("expected BPF module get program to be called, but was not")
	}
}

func TestBPFRunnerProgramAttachTracepointError(t *testing.T) {
	mockError := errors.New("mock BPF attach tracepoint error")
	mockProgram := newMockBPFProgram(mockError)
	mockModule := newMockBPFModule(mockProgram, nil, nil, nil, nil)
	mockBPFModuleCreator := newMockBPFModuleCreator(mockModule, nil)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockProgram.attachTracepointCalled {
		t.Error("expected tracepoint to be attached to BPF program, but was not")
	}
}

func TestBPFRunnerModuleInitPerfBufferError(t *testing.T) {
	mockError := errors.New("mock BPF init perf buffer error")
	mockProgram := newMockBPFProgram(nil)
	mockModule := newMockBPFModule(mockProgram, nil, nil, nil, mockError)
	mockBPFModuleCreator := newMockBPFModuleCreator(mockModule, nil)

	runner := newLibBPFGoBPFRunner(tcpStateChangeEventChannelSize,
		droppedEventsChannelSize,
		tcpStateChangeEventPerfBufSizePages,
		mockBPFModuleCreator)

	err := runner.run()
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}

	if !mockModule.initPerfBufCalled {
		t.Error("expected BPF module perf buffer to be initialised, but was not")
	}
}
