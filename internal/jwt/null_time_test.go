package jwt

import (
	"encoding/json"
	"testing"
)

// TestUnmarshalNullTimeClaim verifies that JSON null for time claims (iat, exp, nbf)
// is treated as "not set" rather than causing an error.
func TestUnmarshalNullTimeClaim(t *testing.T) {
	data := []byte(`{"sub":"alice","iat":null,"exp":null,"nbf":null}`)
	var c Claims
	err := json.Unmarshal(data, &c)
	if err != nil {
		t.Fatalf("null time claim should not cause error, got: %v", err)
	}
	if c.Subject != "alice" {
		t.Fatalf("subject lost: %q", c.Subject)
	}
	if c.IssuedAt != nil {
		t.Fatalf("iat should be nil for null, got %v", c.IssuedAt)
	}
	if c.ExpiresAt != nil {
		t.Fatalf("exp should be nil for null, got %v", c.ExpiresAt)
	}
	if c.NotBefore != nil {
		t.Fatalf("nbf should be nil for null, got %v", c.NotBefore)
	}
}
