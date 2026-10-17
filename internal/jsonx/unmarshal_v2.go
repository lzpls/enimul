//go:build goexperiment.jsonv2

package jsonx

import "encoding/json/v2"

var options = json.DefaultOptionsV2()

func initOptions() {
	if disallowUnknownFields {
		options = json.JoinOptions(options, json.RejectUnknownMembers(true))
	}
}

func Unmarshal(in []byte, out any) error { return json.Unmarshal(in, out, options) }
