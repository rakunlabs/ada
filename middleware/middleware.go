package middleware

import (
	middlewareCors "github.com/rakunlabs/ada/middleware/cors"
	middlewareLog "github.com/rakunlabs/ada/middleware/log"
	middlewareRecover "github.com/rakunlabs/ada/middleware/recover"
	middlewareRequestID "github.com/rakunlabs/ada/middleware/requestid"
)

var (
	Recover   = middlewareRecover.Middleware
	Cors      = middlewareCors.Middleware
	RequestID = middlewareRequestID.Middleware
	Log       = middlewareLog.Middleware
)
