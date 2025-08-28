package telemetry

import (
	"context"
	"net/http"
	"slices"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	"go.opentelemetry.io/otel/semconv/v1.34.0/httpconv"
)

// HTTPMeter is a recorder of HTTP metrics for prometheus. Use NewHTTPMeter to initialize it.
type HTTPMeter struct {
	requestTotal  metric.Int64Counter
	requestActive httpconv.ServerActiveRequests

	requestBodySizeHistogram  httpconv.ServerRequestBodySize
	responseBodySizeHistogram httpconv.ServerResponseBodySize
	requestDurationHistogram  httpconv.ServerRequestDuration
}

func NewHTTPMeter(meter metric.Meter) HTTPMeter {
	m := HTTPMeter{}

	var err error
	m.requestDurationHistogram, err = httpconv.NewServerRequestDuration(
		meter,
		metric.WithExplicitBucketBoundaries(
			0.005, 0.01, 0.025, 0.05, 0.075, 0.1,
			0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10,
		),
	)
	handleErr(err)

	m.requestBodySizeHistogram, err = httpconv.NewServerRequestBodySize(meter)
	handleErr(err)

	m.responseBodySizeHistogram, err = httpconv.NewServerResponseBodySize(meter)
	handleErr(err)

	m.requestActive, err = httpconv.NewServerActiveRequests(meter)
	handleErr(err)

	m.requestTotal, err = NewServerTotalRequests(meter)
	handleErr(err)

	return m
}

func NewServerTotalRequests(meter metric.Meter) (metric.Int64Counter, error) {
	if meter == nil {
		return noop.Int64Counter{}, nil
	}

	return meter.Int64Counter(
		"http.server.total_requests",
		metric.WithDescription("Total number of requests."),
		metric.WithUnit("{request}"),
	)
}

type MetricData struct {
	ResponseSize         int64
	RequestSize          int64
	AdditionalAttributes []attribute.KeyValue
	ElapsedTime          float64
	StatusCode           int
	Request              *http.Request
}

var metricRecordOptionPool = &sync.Pool{
	New: func() any {
		return &[]metric.RecordOption{}
	},
}

func (m *HTTPMeter) Record(ctx context.Context, data MetricData) {
	attributes := MetricAttributes(data.Request, data.StatusCode, data.AdditionalAttributes)
	o := metric.WithAttributeSet(attribute.NewSet(attributes...))
	recordOpts := metricRecordOptionPool.Get().(*[]metric.RecordOption)
	*recordOpts = append(*recordOpts, o)
	m.requestBodySizeHistogram.Inst().Record(ctx, data.RequestSize, *recordOpts...)
	m.responseBodySizeHistogram.Inst().Record(ctx, data.ResponseSize, *recordOpts...)
	m.requestDurationHistogram.Inst().Record(ctx, data.ElapsedTime/1000.0, o)
	m.requestTotal.Add(ctx, 1, o)
	*recordOpts = (*recordOpts)[:0]
	metricRecordOptionPool.Put(recordOpts)
}

func MetricAttributes(r *http.Request, statusCode int, additionalAttributes []attribute.KeyValue) []attribute.KeyValue {
	num := len(additionalAttributes)
	protoName, protoVersion := netProtocol(r.Proto)
	if protoName != "" {
		num++
	}
	if protoVersion != "" {
		num++
	}

	if statusCode > 0 {
		num++
	}

	attributes := slices.Grow(additionalAttributes, num)
	attributes = append(attributes,
		semconv.HTTPRequestMethodKey.String(standardizeHTTPMethod(r.Method)),
		schemeReq(r),
	)

	if protoName != "" {
		attributes = append(attributes, semconv.NetworkProtocolName(protoName))
	}
	if protoVersion != "" {
		attributes = append(attributes, semconv.NetworkProtocolVersion(protoVersion))
	}

	if statusCode > 0 {
		attributes = append(attributes, semconv.HTTPResponseStatusCode(statusCode))
	}
	return attributes
}
