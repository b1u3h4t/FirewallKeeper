package volcapi

import "testing"

func TestParsePort(t *testing.T) {
	s, e, err := ParsePort("22")
	if err != nil || s != 22 || e != 22 {
		t.Fatalf("got %d-%d %v", s, e, err)
	}
	s, e, err = ParsePort("8000-9000")
	if err != nil || s != 8000 || e != 9000 {
		t.Fatalf("got %d-%d %v", s, e, err)
	}
}
