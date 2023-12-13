package acator

import (
	"encoding/base64"
	"testing"

	"github.com/findy-network/findy-agent-auth/acator/cose"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestDart(t *testing.T) {
	defer assert.PushTester(t)()
	
	dartCose := "pgECAkTf0aqXAyYgASHCWCBcXBBfGtX3lKuHcms9HojH/jZ5lJXRS9l3qBY8yiHQEyLCWCC9fjTHfVna0h4YKJOKpUXAdxcfq3c/S24tf6Jd4SScyw=="
	dartCoseData := try.To1(base64.StdEncoding.DecodeString(dartCose))
	dartCoseKey := try.To1(cose.NewFromData(dartCoseData))
	println("--- dart cose key ---")
	println(dartCoseKey)
}
