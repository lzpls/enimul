//go:build goexperiment.jsonv2

package main

import (
	"encoding/json/v2"

	"github.com/lzpls/enimul/internal/core"
)

func decodeConfig(data []byte, rejectUnknownMembers bool) (*core.Config, error) {
	cfg := new(core.Config)
	opts := json.JoinOptions(json.DefaultOptionsV2(), json.RejectUnknownMembers(rejectUnknownMembers))
	if err := json.Unmarshal(data, cfg, opts); err != nil {
		return nil, err
	}
	return cfg, nil
}
