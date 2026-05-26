package backend

import (
	"errors"
	"fmt"
	"log"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/hetznerrobot"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
)

type HetznerRobot struct {
	name       string
	client     *hetznerrobot.FirewallClient
	descPrefix string
}

func NewHetznerRobot(t config.Target, cfg *config.Config) (*HetznerRobot, error) {
	user := firstNonEmptyStr(t.RobotUser, t.AccessKeyID)
	pass := firstNonEmptyStr(t.RobotPassword, t.AccessKeySecret)
	serverNum := firstNonEmptyStr(t.InstanceID, t.ServerNumber)
	if serverNum == "" {
		return nil, fmt.Errorf("需要 server_number 或 instance_id")
	}
	return &HetznerRobot{
		name: t.Name,
		client: hetznerrobot.NewFirewall(
			user,
			pass,
			t.Endpoint,
			serverNum,
		),
		descPrefix: cfg.RuleDescription,
	}, nil
}

func (b *HetznerRobot) Name() string { return b.name }

func (b *HetznerRobot) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := cfg.Protocol

	for _, port := range cfg.Ports {
		ruleName := ruleDescription(cfg, port, 64)
		if err := b.upsertRule(proto, port, cidr, ruleName); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range cfg.Ports {
			if err := b.removeRule(proto, port, oldCIDR); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *HetznerRobot) upsertRule(proto, port, cidr, ruleName string) error {
	err := b.client.UpsertInbound(proto, port, cidr, ruleName)
	if err != nil {
		if isHetznerRobotInProcess(err) {
			return fmt.Errorf("防火墙正在更新中，请稍后重试: %w", err)
		}
		if isHetznerRobotRuleLimit(err) {
			return fmt.Errorf("Robot 防火墙入站规则已达上限(10条): %w", err)
		}
		if isDuplicate(err) {
			log.Printf("[%s] 防火墙规则已存在，跳过: %s %s %s", b.name, cidr, proto, port)
			return nil
		}
		return fmt.Errorf("POST firewall: %w", err)
	}
	log.Printf("[%s] 已添加 Hetzner Robot 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func (b *HetznerRobot) removeRule(proto, port, cidr string) error {
	err := b.client.RemoveInbound(proto, port, cidr, b.descPrefix)
	if err != nil {
		if isHetznerRobotInProcess(err) {
			return fmt.Errorf("防火墙正在更新中，请稍后重试: %w", err)
		}
		if isNotFound(err) {
			log.Printf("[%s] 旧防火墙规则不存在，跳过: %s %s", b.name, cidr, port)
			return nil
		}
		return fmt.Errorf("POST firewall: %w", err)
	}
	log.Printf("[%s] 已删除旧 Hetzner Robot 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func isHetznerRobotInProcess(err error) bool {
	var apiErr *hetznerrobot.APIError
	return errors.As(err, &apiErr) && apiErr.Code == "FIREWALL_IN_PROCESS"
}

func isHetznerRobotRuleLimit(err error) bool {
	var apiErr *hetznerrobot.APIError
	return errors.As(err, &apiErr) && apiErr.Code == "FIREWALL_RULE_LIMIT_EXCEEDED"
}

var _ Backend = (*HetznerRobot)(nil)
