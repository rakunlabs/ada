package securecookie

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
)

// Serializer converts a value to and from a byte slice before it is signed and
// optionally encrypted.
type Serializer interface {
	// Serialize encodes src into a byte slice.
	Serialize(src any) ([]byte, error)
	// Deserialize decodes src into dst. dst must be a non-nil pointer.
	Deserialize(src []byte, dst any) error
}

// GobSerializer encodes values using encoding/gob. It is the default and
// supports arbitrary Go types. Concrete types stored behind an interface value
// must be registered with gob.Register.
type GobSerializer struct{}

// Serialize implements Serializer.
func (GobSerializer) Serialize(src any) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Deserialize implements Serializer.
func (GobSerializer) Deserialize(src []byte, dst any) error {
	return gob.NewDecoder(bytes.NewReader(src)).Decode(dst)
}

// JSONSerializer encodes values using encoding/json. It produces smaller,
// human-readable payloads but only supports JSON-compatible types.
type JSONSerializer struct{}

// Serialize implements Serializer.
func (JSONSerializer) Serialize(src any) ([]byte, error) {
	return json.Marshal(src)
}

// Deserialize implements Serializer.
func (JSONSerializer) Deserialize(src []byte, dst any) error {
	return json.Unmarshal(src, dst)
}
