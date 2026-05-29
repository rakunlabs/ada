package sessions

// flashesKey is the default Values key under which flash messages are stored.
const flashesKey = "_flash"

// AddFlash queues a flash message. Flash messages are read once: the next call
// to Flashes returns and clears them.
//
// Pass an optional key to use a separate bucket instead of the default one.
func (s *Session) AddFlash(value any, vars ...string) {
	key := flashesKey
	if len(vars) > 0 {
		key = vars[0]
	}

	var flashes []any
	if existing, ok := s.Values[key].([]any); ok {
		flashes = existing
	}

	s.Values[key] = append(flashes, value)
}

// Flashes returns and removes the queued flash messages. Pass an optional key to
// read a non-default bucket. It returns nil when there are none.
func (s *Session) Flashes(vars ...string) []any {
	key := flashesKey
	if len(vars) > 0 {
		key = vars[0]
	}

	v, ok := s.Values[key]
	if !ok {
		return nil
	}

	delete(s.Values, key)

	flashes, _ := v.([]any)

	return flashes
}
