package jsonx

import (
	"bytes"
	"encoding/json"
	"io"
)

var disallowUnknownFields = false

func DisallowUnknownFields() {
	disallowUnknownFields = true
	initOptions()
}

func newDecoder(r io.Reader) *json.Decoder {
	decoder := json.NewDecoder(r)
	if disallowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	return decoder
}

func newDecoderFromBytes(b []byte) *json.Decoder {
	return newDecoder(bytes.NewReader(b))
}
