package ip_test

import (
	"testing"

	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
)

func TestFetchPublicIPv4(t *testing.T) {
	if testing.Short() {
		t.Skip("skip network test in -short mode")
	}
	got, err := ip.FetchPublicIPv4([]string{"https://4.ipw.cn"})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("empty ip")
	}
	t.Log("public ip:", got)
}

func TestToCIDR(t *testing.T) {
	if ip.ToCIDR("1.2.3.4") != "1.2.3.4/32" {
		t.Fatal("expected /32 suffix")
	}
}
