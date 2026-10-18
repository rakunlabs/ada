package encoding

import (
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// encoder is a resettable compressing writer.
type encoder interface {
	io.WriteCloser
	Flush() error
	Reset(w io.Writer)
}

type encoderPool struct {
	pool sync.Pool
}

func (p *encoderPool) get(w io.Writer) encoder {
	e := p.pool.Get().(encoder)
	e.Reset(w)

	return e
}

func (p *encoderPool) put(e encoder) {
	// Drop the reference to the response writer before pooling.
	e.Reset(io.Discard)
	p.pool.Put(e)
}

func newGzipPool(level *int) (*encoderPool, error) {
	l := gzip.DefaultCompression
	if level != nil {
		l = *level
	}

	if _, err := gzip.NewWriterLevel(io.Discard, l); err != nil {
		return nil, fmt.Errorf("gzip level: %w", err)
	}

	return &encoderPool{pool: sync.Pool{New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, l)

		return w
	}}}, nil
}

func newBrotliPool(level *int) (*encoderPool, error) {
	// 4 is a good speed/ratio balance for dynamic content; 11 suits static assets.
	l := 4
	if level != nil {
		l = *level
	}

	if l < brotli.BestSpeed || l > brotli.BestCompression {
		return nil, fmt.Errorf("brotli level must be between %d and %d", brotli.BestSpeed, brotli.BestCompression)
	}

	return &encoderPool{pool: sync.Pool{New: func() any {
		return brotli.NewWriterLevel(io.Discard, l)
	}}}, nil
}

func newZstdPool(level *int) (*encoderPool, error) {
	l := zstd.SpeedDefault
	if level != nil {
		if *level < 1 || *level > 22 {
			return nil, fmt.Errorf("zstd level must be between 1 and 22")
		}

		l = zstd.EncoderLevelFromZstd(*level)
	}

	opts := []zstd.EOption{
		zstd.WithEncoderLevel(l),
		// Synchronous encoding keeps flushes (SSE) immediate and memory low.
		zstd.WithEncoderConcurrency(1),
		// Browsers limit the zstd window size to 8 MiB.
		zstd.WithWindowSize(1 << 23),
	}

	if _, err := zstd.NewWriter(nil, opts...); err != nil {
		return nil, fmt.Errorf("zstd options: %w", err)
	}

	return &encoderPool{pool: sync.Pool{New: func() any {
		e, _ := zstd.NewWriter(nil, opts...)

		return e
	}}}, nil
}
