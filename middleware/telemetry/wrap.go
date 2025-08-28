package telemetry

import (
	"io"
	"sync"
)

var _ io.ReadCloser = &BodyWrapper{}

// BodyWrapper wraps a http.Request.Body (an io.ReadCloser) to track the number
// of bytes read and the last error.
type BodyWrapper struct {
	io.ReadCloser

	mu   sync.Mutex
	read int64
}

// NewBodyWrapper creates a new BodyWrapper.
//
// The onRead attribute is a callback that will be called every time the data
// is read, with the number of bytes being read.
func NewBodyWrapper(body io.ReadCloser) *BodyWrapper {
	return &BodyWrapper{
		ReadCloser: body,
	}
}

// Read reads the data from the io.ReadCloser, and stores the number of bytes
// read and the error.
func (w *BodyWrapper) Read(b []byte) (int, error) {
	n, err := w.ReadCloser.Read(b)
	n1 := int64(n)

	w.updateReadData(n1)
	return n, err
}

func (w *BodyWrapper) updateReadData(n int64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.read += n
}

// Close closes the io.ReadCloser.
func (w *BodyWrapper) Close() error {
	return w.ReadCloser.Close()
}

// BytesRead returns the number of bytes read up to this point.
func (w *BodyWrapper) BytesRead() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.read
}
