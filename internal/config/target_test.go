package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestParseMultipleTargets(t *testing.T) {
	raw := `
ports: ["22"]
targets:
  tencent_lighthouse:
    enabled: true
    region: ap-beijing
    secret_id: id
    secret_key: key
    instance_id: lhins-1
  aliyun_swas:
    enabled: true
    region: us-east-1
    access_key_id: ak
    access_key_secret: sk
    instance_id: swas-1
`
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(raw), &fc); err != nil {
		t.Fatal(err)
	}
	targets, err := buildTargets(fc)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(targets))
	}
}

func TestLegacyBackendCompat(t *testing.T) {
	raw := fileConfig{
		Backend: "lighthouse",
		Tencent: Tencent{SecretID: "id", SecretKey: "key", Region: "ap-beijing"},
		Lighthouse: Lighthouse{InstanceID: "lhins-1"},
	}
	tg := legacyTarget(raw)
	if tg == nil {
		t.Fatal("expected legacy target")
	}
	if tg.Provider != ProviderTencentLighthouse {
		t.Fatalf("got %s", tg.Provider)
	}
}

func TestParseScalewayTarget(t *testing.T) {
	raw := `
ports: ["22"]
targets:
  scaleway_vps:
    provider: scaleway_security_group
    enabled: true
    zone: fr-par-1
    secret_key: scw-key
    security_group_id: sg-uuid
`
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(raw), &fc); err != nil {
		t.Fatal(err)
	}
	targets, err := buildTargets(fc)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	if targets[0].Provider != ProviderScalewaySG {
		t.Fatalf("provider %s", targets[0].Provider)
	}
	if targets[0].Zone != "fr-par-1" {
		t.Fatalf("zone %s", targets[0].Zone)
	}
}

func TestParseHetznerTargets(t *testing.T) {
	raw := `
ports: ["22"]
targets:
  hcloud_fw:
    provider: hetzner_cloud_firewall
    enabled: true
    api_token: tok
    firewall_id: "12345"
  hetzner_ded:
    provider: hetzner_robot_firewall
    enabled: true
    robot_user: user
    robot_password: pass
    server_number: "321"
`
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(raw), &fc); err != nil {
		t.Fatal(err)
	}
	targets, err := buildTargets(fc)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(targets))
	}
}

func TestParseAWSVolcTargets(t *testing.T) {
	raw := `
ports: ["22"]
targets:
  aws_ls:
    provider: aws_lightsail
    enabled: true
    region: us-east-1
    access_key_id: AKIA
    access_key_secret: secret
    instance_name: MyInstance
  volc_sg:
    provider: volcengine_security_group
    enabled: true
    region: cn-beijing
    access_key_id: ak
    access_key_secret: sk
    security_group_id: sg-xxx
`
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(raw), &fc); err != nil {
		t.Fatal(err)
	}
	targets, err := buildTargets(fc)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("want 2, got %d", len(targets))
	}
}

func TestParseNetcupTarget(t *testing.T) {
	raw := `
ports: ["22"]
targets:
  netcup_vps:
    provider: netcup_scp_firewall
    enabled: true
    refresh_token: rt-xxx
    firewall_policy_id: "42"
    server_id: "100"
    interface_mac: "aa:bb:cc:dd:ee:ff"
`
	var fc fileConfig
	if err := yaml.Unmarshal([]byte(raw), &fc); err != nil {
		t.Fatal(err)
	}
	targets, err := buildTargets(fc)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Provider != ProviderNetcupSCPFirewall {
		t.Fatalf("got %+v", targets)
	}
}

func TestDisabledTargetSkipped(t *testing.T) {
	raw := fileConfig{
		Targets: map[string]targetYAML{
			"tencent_cvm": {Enabled: boolPtr(false), Region: "ap-beijing", SecretID: "a", SecretKey: "b", SecurityGroupID: "sg"},
		},
	}
	_, err := buildTargets(raw)
	if err == nil || !strings.Contains(err.Error(), "没有任何 enabled") {
		t.Fatalf("expected no enabled error, got %v", err)
	}
}

func boolPtr(v bool) *bool { return &v }
