package ada

type Logger interface {
	Error(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
}
