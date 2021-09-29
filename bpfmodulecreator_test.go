package main

import (
	"errors"
	"testing"
)

type mockBPFObjectLoader struct {
	errorToReturn error

	loadCalled bool
}

func newMockBPFObjectLoader(errorToReturn error) *mockBPFObjectLoader {
	return &mockBPFObjectLoader{errorToReturn: errorToReturn}
}

func (ml *mockBPFObjectLoader) load() ([]byte, error) {
	ml.loadCalled = true

	if ml.errorToReturn != nil {
		return nil, ml.errorToReturn
	}

	return nil, nil
}

func TestBPFModuleCreatorObjectLoaderError(t *testing.T) {
	mockError := errors.New("mock BPF object loader error")
	mockObjectLoader := newMockBPFObjectLoader(mockError)

	moduleCreator := newLibBPFGoBPFModuleCreator(mockObjectLoader)

	_, err := moduleCreator.createModule("mock-module")
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !errors.Is(err, mockError) {
		t.Errorf("expected error chain to include %q, but did not", mockError)
	}
}
