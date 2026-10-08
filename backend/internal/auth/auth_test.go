package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format %s", h)
	}
	if !VerifyPassword(h, "correct horse battery staple") || VerifyPassword(h, "wrong") {
		t.Fatal("verification failed")
	}
	h2, _ := HashPassword("correct horse battery staple")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 test vector (SHA1): secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> last 6: 287082
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := TOTPCode(secret, time.Unix(59, 0)); got != "287082" {
		t.Fatalf("got %s", got)
	}
	if got := TOTPCode(secret, time.Unix(1111111109, 0)); got != "081804" {
		t.Fatalf("got %s", got)
	}
	now := time.Unix(1111111109, 0)
	if _, ok := VerifyTOTP(secret, "081804", now.Add(25*time.Second)); !ok {
		t.Fatal("drift +1 step should be accepted")
	}
	if _, ok := VerifyTOTP(secret, "081804", now.Add(5*time.Minute)); ok {
		t.Fatal("old code should be rejected")
	}
}

func TestRoles(t *testing.T) {
	if !Allows(RoleAdmin, RoleEditor) || Allows(RoleViewer, RoleEditor) || Allows("bogus", RoleViewer) {
		t.Fatal("role ranking wrong")
	}
}
