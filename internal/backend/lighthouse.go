package backend

import (
	"fmt"
	"log"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/tencentapi"
)

type Lighthouse struct {
	client *tencentapi.LighthouseClient
}

func NewLighthouse(cfg *config.Config) (*Lighthouse, error) {
	return &Lighthouse{
		client: tencentapi.NewLighthouse(
			cfg.Tencent.SecretID,
			cfg.Tencent.SecretKey,
			cfg.Tencent.Region,
			cfg.LighthouseInstanceID,
		),
	}, nil
}

func (b *Lighthouse) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	for _, port := range cfg.Ports {
		if err := b.createRule(cfg, cidr, port); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range cfg.Ports {
			if err := b.deleteRule(cfg, oldCIDR, port); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Lighthouse) createRule(cfg *config.Config, cidr, port string) error {
	err := b.client.CreateRules([]tencentapi.FirewallRule{{
		Protocol:                cfg.Protocol,
		Port:                    port,
		CidrBlock:               cidr,
		Action:                  "ACCEPT",
		FirewallRuleDescription: ruleDescription(cfg, port, 64),
	}})
	if err != nil {
		if isDuplicate(err) {
			log.Printf("规则已存在，跳过: %s %s %s", cidr, cfg.Protocol, port)
			return nil
		}
		return fmt.Errorf("CreateFirewallRules: %w", err)
	}
	log.Printf("已添加轻量防火墙规则: %s %s %s", cidr, cfg.Protocol, port)
	return nil
}

func (b *Lighthouse) deleteRule(cfg *config.Config, cidr, port string) error {
	err := b.client.DeleteRules([]tencentapi.FirewallRule{{
		Protocol:  cfg.Protocol,
		Port:      port,
		CidrBlock: cidr,
		Action:    "ACCEPT",
	}})
	if err != nil {
		if isNotFound(err) {
			log.Printf("旧规则不存在，跳过删除: %s %s", cidr, port)
			return nil
		}
		return fmt.Errorf("DeleteFirewallRules: %w", err)
	}
	log.Printf("已删除旧轻量防火墙规则: %s %s %s", cidr, cfg.Protocol, port)
	return nil
}

var _ Backend = (*Lighthouse)(nil)
