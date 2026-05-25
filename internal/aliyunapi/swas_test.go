package aliyunapi

import "testing"

func TestFormatPort(t *testing.T) {
	if formatPort("22") != "22/22" {
		t.Fatalf("want 22/22")
	}
	if formatPort("22/22") != "22/22" {
		t.Fatalf("keep range format")
	}
}

func TestNormalizePort(t *testing.T) {
	if normalizePort("22/22") != "22" {
		t.Fatalf("want 22")
	}
	if normalizePort("3306") != "3306" {
		t.Fatalf("want 3306")
	}
}

func TestPortEqual(t *testing.T) {
	if !portEqual("22", "22/22") {
		t.Fatal("22 should equal 22/22")
	}
}
