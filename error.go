package ada

var DefaultErrHandler = func(c *Context, err error) {
	c.SendJSON(map[string]string{"message": err.Error()})
}
