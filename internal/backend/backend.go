package backend

import (
	"fmt"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
)

type Backend interface {
	UpsertWhitelist(ip string, oldIP *string, cfg *config.Config) error
}

func New(cfg *config.Config) (Backend, error) {
	switch cfg.Backend {
	case "lighthouse":
		return NewLighthouse(cfg)
	case "cvm":
		return NewCVM(cfg)
	default:
		return nil, fmt.Errorf("unknown backend: %s", cfg.Backend)
	}
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
