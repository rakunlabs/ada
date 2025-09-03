package grpc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"

	v1 "github.com/rakunlabs/ada/_examples/grpc/protobuf/gen/test/v1"
	"github.com/rakunlabs/ada/_examples/grpc/protobuf/gen/test/v1/testv1connect"
)

type HelloHandler struct {
	otelInterceptor *otelconnect.Interceptor
}

var _ testv1connect.MyServiceHandler = (*HelloHandler)(nil)

func NewHelloHandler() *HelloHandler {
	otelInterceptor, err := otelconnect.NewInterceptor(
		otelconnect.WithoutServerPeerAttributes(),
		otelconnect.WithTraceRequestHeader("X-Request-Id", "User-Agent"),
	)
	if err != nil {
		panic(err)
	}

	return &HelloHandler{
		otelInterceptor: otelInterceptor,
	}
}

func (h *HelloHandler) Handler() (string, http.Handler) {
	return testv1connect.NewMyServiceHandler(h, connect.WithInterceptors(h.otelInterceptor))
}

func (h *HelloHandler) ServiceName() string {
	return testv1connect.MyServiceName
}

func (h *HelloHandler) GetRecord(ctx context.Context, req *connect.Request[v1.GetRecordRequest]) (*connect.Response[v1.GetRecordResponse], error) {
	if req.Msg.GetId() == 0 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("record not found"))
	}

	return &connect.Response[v1.GetRecordResponse]{
		Msg: &v1.GetRecordResponse{
			Id:            req.Msg.GetId(),
			RecordDetails: json.RawMessage(`{"name": "Sample Record", "value": 42}`),
		},
	}, nil
}
