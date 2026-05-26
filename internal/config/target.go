package config

import (
	"fmt"
	"strings"
)

const (
	ProviderTencentLighthouse = "tencent_lighthouse"
	ProviderTencentCVM        = "tencent_cvm"
	ProviderAliyunSWAS         = "aliyun_swas"
	ProviderScalewaySG          = "scaleway_security_group"
	ProviderHetznerCloudFirewall = "hetzner_cloud_firewall"
	ProviderHetznerRobotFirewall = "hetzner_robot_firewall"
	ProviderAWSLightsail         = "aws_lightsail"
	ProviderVolcengineSG         = "volcengine_security_group"
	ProviderNetcupSCPFirewall    = "netcup_scp_firewall"
)

// Target 表示一个待更新的防火墙目标（一台实例或一个安全组）。
type Target struct {
	Name     string
	Provider string
	Enabled  bool
	Region   string

	// 腾讯云
	SecretID        string
	SecretKey       string
	InstanceID      string
	SecurityGroupID string

	// 阿里云
	AccessKeyID     string
	AccessKeySecret string
	Endpoint        string

	// Scaleway（可用区，如 fr-par-1）
	Zone string

	// Hetzner Cloud 防火墙 ID；Robot 独立服务器编号
	FirewallID   string
	RobotUser    string
	RobotPassword string
	ServerNumber string

	// AWS Lightsail 使用实例名称（非 ID）
	InstanceName string

	// Netcup SCP OAuth
	RefreshToken string
	APIToken     string
	UserID       string
	InterfaceMAC string
}

type targetYAML struct {
	Provider        string `yaml:"provider"`
	Enabled         *bool  `yaml:"enabled"`
	Region          string `yaml:"region"`
	SecretID        string `yaml:"secret_id"`
	SecretKey       string `yaml:"secret_key"`
	InstanceID      string `yaml:"instance_id"`
	SecurityGroupID string `yaml:"security_group_id"`
	AccessKeyID     string `yaml:"access_key_id"`
	AccessKeySecret string `yaml:"access_key_secret"`
	Endpoint        string `yaml:"endpoint"`
	Zone            string `yaml:"zone"`
	APIToken        string `yaml:"api_token"`
	FirewallID      string `yaml:"firewall_id"`
	FirewallPolicyID string `yaml:"firewall_policy_id"`
	RobotUser       string `yaml:"robot_user"`
	RobotPassword   string `yaml:"robot_password"`
	ServerNumber    string `yaml:"server_number"`
	InstanceName    string `yaml:"instance_name"`
	RefreshToken    string `yaml:"refresh_token"`
	AccessToken     string `yaml:"access_token"`
	UserID          string `yaml:"user_id"`
	InterfaceMAC    string `yaml:"interface_mac"`
}

func buildTargets(raw fileConfig) ([]Target, error) {
	if len(raw.Targets) > 0 {
		return parseTargetsMap(raw.Targets)
	}
	// 兼容旧版单 backend 配置
	if legacy := legacyTarget(raw); legacy != nil {
		return []Target{*legacy}, nil
	}
	return nil, fmt.Errorf("未配置任何 targets，请在 targets 下启用至少一个厂商目标")
}

func parseTargetsMap(m map[string]targetYAML) ([]Target, error) {
	var out []Target
	for name, t := range m {
		provider := t.Provider
		if provider == "" {
			provider = name
		}
		enabled := true
		if t.Enabled != nil {
			enabled = *t.Enabled
		}
		if !enabled {
			continue
		}

		target := Target{
			Name:            name,
			Provider:        provider,
			Enabled:         true,
			Region:          t.Region,
			SecretID:        t.SecretID,
			SecretKey:       t.SecretKey,
			InstanceID:      t.InstanceID,
			SecurityGroupID: t.SecurityGroupID,
			AccessKeyID:     t.AccessKeyID,
			AccessKeySecret: t.AccessKeySecret,
			Endpoint:        t.Endpoint,
			Zone:            firstNonEmpty(t.Zone, t.Region),
			FirewallID:      firstNonEmpty(t.FirewallID, t.FirewallPolicyID, t.SecurityGroupID),
			RobotUser:       t.RobotUser,
			RobotPassword:   t.RobotPassword,
			ServerNumber:    firstNonEmpty(t.ServerNumber, t.InstanceID),
			InstanceName:    firstNonEmpty(t.InstanceName, t.InstanceID),
			RefreshToken:    t.RefreshToken,
			APIToken:        firstNonEmpty(t.AccessToken, t.APIToken),
			UserID:          t.UserID,
			InterfaceMAC:    t.InterfaceMAC,
		}
		if target.SecretKey == "" && target.Provider != ProviderNetcupSCPFirewall {
			target.SecretKey = t.APIToken
		}
		applyTargetEnvDefaults(&target)
		if err := validateTarget(target); err != nil {
			return nil, fmt.Errorf("targets.%s: %w", name, err)
		}
		out = append(out, target)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("targets 中没有任何 enabled: true 的目标")
	}
	return out, nil
}

func applyTargetEnvDefaults(t *Target) {
	switch t.Provider {
	case ProviderTencentLighthouse, ProviderTencentCVM:
		t.SecretID = envOr(t.SecretID, "TENCENT_SECRET_ID")
		t.SecretKey = envOr(t.SecretKey, "TENCENT_SECRET_KEY")
		if t.Region == "" {
			t.Region = envOr("", "TENCENT_REGION")
		}
		if t.Provider == ProviderTencentLighthouse && t.InstanceID == "" {
			t.InstanceID = envOr("", "LIGHTHOUSE_INSTANCE_ID")
		}
		if t.Provider == ProviderTencentCVM && t.SecurityGroupID == "" {
			t.SecurityGroupID = envOr("", "SECURITY_GROUP_ID")
		}
	case ProviderAliyunSWAS:
		t.AccessKeyID = envOr(t.AccessKeyID, "ALIBABA_CLOUD_ACCESS_KEY_ID")
		t.AccessKeySecret = envOr(t.AccessKeySecret, "ALIBABA_CLOUD_ACCESS_KEY_SECRET")
		if t.Region == "" {
			t.Region = envOr("", "ALIBABA_CLOUD_REGION")
		}
		if t.InstanceID == "" {
			t.InstanceID = envOr("", "ALIBABA_CLOUD_SWAS_INSTANCE_ID")
		}
		if t.Endpoint == "" {
			t.Endpoint = envOr("", "ALIBABA_CLOUD_ENDPOINT")
		}
	case ProviderScalewaySG:
		t.SecretKey = envOr(t.SecretKey, "SCW_SECRET_KEY")
		if t.SecretKey == "" {
			t.SecretKey = envOr("", "SCW_API_TOKEN")
		}
		if t.Zone == "" {
			t.Zone = envOr(t.Region, "SCW_DEFAULT_ZONE")
		}
		if t.SecurityGroupID == "" {
			t.SecurityGroupID = envOr("", "SCW_SECURITY_GROUP_ID")
		}
	case ProviderHetznerCloudFirewall:
		t.SecretKey = envOr(t.SecretKey, "HCLOUD_TOKEN")
		if t.FirewallID == "" {
			t.FirewallID = envOr(t.SecurityGroupID, "HCLOUD_FIREWALL_ID")
		}
		if t.Endpoint == "" {
			t.Endpoint = envOr("", "HCLOUD_ENDPOINT")
		}
	case ProviderHetznerRobotFirewall:
		t.RobotUser = envOr(t.RobotUser, "HETZNER_ROBOT_USER")
		if t.RobotUser == "" {
			t.RobotUser = envOr(t.AccessKeyID, "ROBOT_USER")
		}
		t.RobotPassword = envOr(t.RobotPassword, "HETZNER_ROBOT_PASSWORD")
		if t.RobotPassword == "" {
			t.RobotPassword = envOr(t.AccessKeySecret, "ROBOT_PASSWORD")
		}
		if t.ServerNumber == "" {
			t.ServerNumber = envOr(t.InstanceID, "HETZNER_ROBOT_SERVER_NUMBER")
		}
		if t.Endpoint == "" {
			t.Endpoint = envOr("", "HETZNER_ROBOT_ENDPOINT")
		}
	case ProviderAWSLightsail:
		t.AccessKeyID = envOr(t.AccessKeyID, "AWS_ACCESS_KEY_ID")
		if t.AccessKeyID == "" {
			t.AccessKeyID = envOr("", "AWS_ACCESS_KEY")
		}
		t.AccessKeySecret = envOr(t.AccessKeySecret, "AWS_SECRET_ACCESS_KEY")
		if t.Region == "" {
			t.Region = envOr("", "AWS_REGION")
		}
		if t.InstanceName == "" {
			t.InstanceName = envOr(t.InstanceID, "AWS_LIGHTSAIL_INSTANCE_NAME")
		}
	case ProviderVolcengineSG:
		t.AccessKeyID = envOr(t.AccessKeyID, "VOLCENGINE_ACCESS_KEY_ID")
		if t.AccessKeyID == "" {
			t.AccessKeyID = envOr("", "VOLC_ACCESSKEY")
		}
		t.AccessKeySecret = envOr(t.AccessKeySecret, "VOLCENGINE_SECRET_ACCESS_KEY")
		if t.AccessKeySecret == "" {
			t.AccessKeySecret = envOr("", "VOLC_SECRETKEY")
		}
		if t.Region == "" {
			t.Region = envOr("", "VOLCENGINE_REGION")
		}
		if t.SecurityGroupID == "" {
			t.SecurityGroupID = envOr("", "VOLCENGINE_SECURITY_GROUP_ID")
		}
		if t.Endpoint == "" {
			t.Endpoint = envOr("", "VOLCENGINE_ENDPOINT")
		}
	case ProviderNetcupSCPFirewall:
		t.RefreshToken = envOr(t.RefreshToken, "NETCUP_SCP_REFRESH_TOKEN")
		t.APIToken = envOr(t.APIToken, "NETCUP_SCP_ACCESS_TOKEN")
		if t.FirewallID == "" {
			t.FirewallID = envOr(t.SecurityGroupID, "NETCUP_FIREWALL_POLICY_ID")
		}
		if t.Endpoint == "" {
			t.Endpoint = envOr("", "NETCUP_SCP_API_URL")
		}
	}
}

func validateTarget(t Target) error {
	switch t.Provider {
	case ProviderTencentLighthouse:
		if t.SecretID == "" || t.SecretKey == "" || t.Region == "" {
			return fmt.Errorf("需要 secret_id、secret_key、region")
		}
		if t.InstanceID == "" {
			return fmt.Errorf("需要 instance_id")
		}
	case ProviderTencentCVM:
		if t.SecretID == "" || t.SecretKey == "" || t.Region == "" {
			return fmt.Errorf("需要 secret_id、secret_key、region")
		}
		if t.SecurityGroupID == "" {
			return fmt.Errorf("需要 security_group_id")
		}
	case ProviderAliyunSWAS:
		if t.AccessKeyID == "" || t.AccessKeySecret == "" || t.Region == "" {
			return fmt.Errorf("需要 access_key_id、access_key_secret、region")
		}
		if t.InstanceID == "" {
			return fmt.Errorf("需要 instance_id")
		}
	case ProviderScalewaySG:
		if t.SecretKey == "" {
			return fmt.Errorf("需要 secret_key 或 api_token（Scaleway API Secret Key）")
		}
		if t.Zone == "" {
			return fmt.Errorf("需要 zone（可用区，如 fr-par-1）或 region")
		}
		if t.SecurityGroupID == "" {
			return fmt.Errorf("需要 security_group_id")
		}
	case ProviderHetznerCloudFirewall:
		if t.SecretKey == "" {
			return fmt.Errorf("需要 api_token 或 secret_key（HCLOUD_TOKEN）")
		}
		if t.FirewallID == "" {
			return fmt.Errorf("需要 firewall_id（HCLOUD_FIREWALL_ID）")
		}
	case ProviderHetznerRobotFirewall:
		if t.RobotUser == "" || t.RobotPassword == "" {
			return fmt.Errorf("需要 robot_user、robot_password（或 access_key_id/access_key_secret）")
		}
		if t.ServerNumber == "" {
			return fmt.Errorf("需要 server_number 或 instance_id")
		}
	case ProviderAWSLightsail:
		if t.AccessKeyID == "" || t.AccessKeySecret == "" {
			return fmt.Errorf("需要 access_key_id、access_key_secret（或 AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY）")
		}
		if t.Region == "" {
			return fmt.Errorf("需要 region（如 us-east-1）")
		}
		if t.InstanceName == "" {
			return fmt.Errorf("需要 instance_name（Lightsail 控制台中的实例名称）")
		}
	case ProviderVolcengineSG:
		if t.AccessKeyID == "" || t.AccessKeySecret == "" || t.Region == "" {
			return fmt.Errorf("需要 access_key_id、access_key_secret、region")
		}
		if t.SecurityGroupID == "" {
			return fmt.Errorf("需要 security_group_id")
		}
	case ProviderNetcupSCPFirewall:
		if t.RefreshToken == "" && t.APIToken == "" {
			return fmt.Errorf("需要 refresh_token 或 access_token（SCP OAuth，见 netcup-cli auth login）")
		}
		if t.FirewallID == "" {
			return fmt.Errorf("需要 firewall_policy_id 或 firewall_id")
		}
	default:
		return fmt.Errorf("不支持的 provider: %s（已知: %s, %s, %s, %s, %s, %s, %s, %s, %s）",
			t.Provider, ProviderTencentLighthouse, ProviderTencentCVM, ProviderAliyunSWAS,
			ProviderScalewaySG, ProviderHetznerCloudFirewall, ProviderHetznerRobotFirewall,
			ProviderAWSLightsail, ProviderVolcengineSG, ProviderNetcupSCPFirewall)
	}
	return nil
}

func legacyTarget(raw fileConfig) *Target {
	backend := stringsTrimLower(raw.Backend)
	if backend == "" && raw.Lighthouse.InstanceID == "" && raw.CVM.SecurityGroupID == "" &&
		raw.AliyunSWAS.InstanceID == "" {
		return nil
	}
	if backend == "" {
		backend = ProviderTencentLighthouse
	}
	// 旧字段名映射
	switch backend {
	case "lighthouse":
		backend = ProviderTencentLighthouse
	case "cvm":
		backend = ProviderTencentCVM
	case "aliyun_swas":
		backend = ProviderAliyunSWAS
	case "scaleway_security_group", "scaleway_sg", "scaleway":
		backend = ProviderScalewaySG
	case "hetzner_cloud_firewall", "hetzner_cloud", "hcloud":
		backend = ProviderHetznerCloudFirewall
	case "hetzner_robot_firewall", "hetzner_robot", "hetzner_dedicated":
		backend = ProviderHetznerRobotFirewall
	case "aws_lightsail", "lightsail":
		backend = ProviderAWSLightsail
	case "volcengine_security_group", "volcengine_sg", "volcengine":
		backend = ProviderVolcengineSG
	case "netcup_scp_firewall", "netcup_firewall", "netcup":
		backend = ProviderNetcupSCPFirewall
	}

	t := Target{
		Name:            backend,
		Provider:        backend,
		Enabled:         true,
		Region:          envOr(raw.Tencent.Region, "TENCENT_REGION"),
		SecretID:        envOr(raw.Tencent.SecretID, "TENCENT_SECRET_ID"),
		SecretKey:       envOr(raw.Tencent.SecretKey, "TENCENT_SECRET_KEY"),
		InstanceID:      envOr(raw.Lighthouse.InstanceID, "LIGHTHOUSE_INSTANCE_ID"),
		SecurityGroupID: envOr(raw.CVM.SecurityGroupID, "SECURITY_GROUP_ID"),
		AccessKeyID:     envOr(raw.Aliyun.AccessKeyID, "ALIBABA_CLOUD_ACCESS_KEY_ID"),
		AccessKeySecret: envOr(raw.Aliyun.AccessKeySecret, "ALIBABA_CLOUD_ACCESS_KEY_SECRET"),
		Endpoint:        envOr(raw.Aliyun.Endpoint, "ALIBABA_CLOUD_ENDPOINT"),
	}
	if backend == ProviderAliyunSWAS {
		t.Region = envOr(raw.Aliyun.Region, "ALIBABA_CLOUD_REGION")
		t.InstanceID = envOr(raw.AliyunSWAS.InstanceID, "ALIBABA_CLOUD_SWAS_INSTANCE_ID")
	} else {
		if t.Region == "" {
			t.Region = envOr(raw.Tencent.Region, "TENCENT_REGION")
		}
	}
	applyTargetEnvDefaults(&t)
	if err := validateTarget(t); err != nil {
		return nil
	}
	return &t
}

func stringsTrimLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
