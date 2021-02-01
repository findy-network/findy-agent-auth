package feature

import "testing"

func TestFeature(t *testing.T) {
	err := Feature()
	if err != nil {
		t.Errorf("Feature test failed %s", err)
	}
}
