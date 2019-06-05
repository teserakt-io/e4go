package e4common

import (
	"testing"
)

func TestValidName(t *testing.T) {

	emptystring := ""

	if err := IsValidName(emptystring); err == nil {
		t.Fatalf("Empty string reported as valid.")
	}
}
