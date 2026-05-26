package backend

import (
	"errors"
	"fmt"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
)

type Backend interface {
	Name() string
	UpsertWhitelist(ip string, oldIP *string, cfg *config.Config) error
}

// NewAll 根据配置创建所有已启用的后端，可并行更新多个云厂商/实例。
func NewAll(cfg *config.Config) ([]Backend, error) {
	var backends []Backend
	for _, t := range cfg.Targets {
		b, err := newTarget(t, cfg)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name, err)
		}
		backends = append(backends, b)
	}
	if len(backends) == 0 {
		return nil, fmt.Errorf("没有已启用的 targets")
	}
	return backends, nil
}

func newTarget(t config.Target, cfg *config.Config) (Backend, error) {
	switch t.Provider {
	case config.ProviderTencentLighthouse:
		return NewLighthouse(t, cfg)
	case config.ProviderTencentCVM:
		return NewCVM(t, cfg)
	case config.ProviderAliyunSWAS:
		return NewAliyunSWAS(t, cfg)
	case config.ProviderScalewaySG:
		return NewScalewaySG(t, cfg)
	case config.ProviderHetznerCloudFirewall:
		return NewHetznerCloud(t, cfg)
	case config.ProviderHetznerRobotFirewall:
		return NewHetznerRobot(t, cfg)
	case config.ProviderAWSLightsail:
		return NewAWSLightsail(t, cfg)
	case config.ProviderVolcengineSG:
		return NewVolcengineSG(t, cfg)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", t.Provider)
	}
}

// UpsertAll 依次更新所有后端；全部成功才返回 nil，否则返回聚合错误。
func UpsertAll(backends []Backend, ip string, oldIP *string, cfg *config.Config) error {
	var errs []error
	for _, b := range backends {
		logPrefix := fmt.Sprintf("[%s]", b.Name())
		if err := b.UpsertWhitelist(ip, oldIP, cfg); err != nil {
			errs = append(errs, fmt.Errorf("%s %w", logPrefix, err))
		}
	}
	return errors.Join(errs...)
}

func ruleDescription(cfg *config.Config, port string, maxLen int) string {
	desc := cfg.RuleDescription + ":" + port
	if len(desc) > maxLen {
		return desc[:maxLen]
	}
	return desc
}

func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exist") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "already") ||
		strings.Contains(msg, "已存在")
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "notfound") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "不存在")
}
