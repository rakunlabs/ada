package mcp

import (
	"bytes"
	"encoding/json"
)

func decodeJSON(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	return decoder.Decode(v)
}
