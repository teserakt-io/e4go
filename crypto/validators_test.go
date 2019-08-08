package crypto

import "testing"

func TestValidateName(t *testing.T) {

	t.Run("Empty string must be invalid", func(t *testing.T) {
		emptystring := ""

		if err := ValidateName(emptystring); err == nil {
			t.Fatalf("Empty string reported as valid.")
		}
	})
}
