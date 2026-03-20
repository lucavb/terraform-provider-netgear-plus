package client

import "testing"

func TestMerge(t *testing.T) {
	t.Parallel()

	if got, want := Merge("password", "1234"), "p1a2s3s4word"; got != want {
		t.Fatalf("Merge() = %q, want %q", got, want)
	}
}

func TestPasswordKDF(t *testing.T) {
	t.Parallel()

	if got, want := PasswordKDF("password", "1234"), "6971092b25576d0b9c254b1216deb1fa"; got != want {
		t.Fatalf("PasswordKDF() = %q, want %q", got, want)
	}
}
