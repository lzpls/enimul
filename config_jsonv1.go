//go:build !goexperiment.jsonv2

package main

import (
	"bytes"
	"encoding/json"

	"github.com/lzpls/enimul/internal/core"
)

// TODO: remove this
func decodeConfig(data []byte, disallowUnknownFields bool) (*core.Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if disallowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	cfg := new(core.Config)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
