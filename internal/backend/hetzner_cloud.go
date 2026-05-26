package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/hetznercloud"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
)

type HetznerCloud struct {
	name       string
	client     *hetznercloud.FirewallClient
	descPrefix string
}

func NewHetznerCloud(t config.Target, cfg *config.Config) (*HetznerCloud, error) {
	firewallID := t.FirewallID
	token := firstNonEmptyStr(t.SecretKey)
	client, err := hetznercloud.NewFirewall(token, firewallID, t.Endpoint)
	if err != nil {
		return nil, err
	}
	return &HetznerCloud{
		name:       t.Name,
		client:     client,
		descPrefix: cfg.RuleDescription,
	}, nil
}

func (b *HetznerCloud) Name() string { return b.name }

func (b *HetznerCloud) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := cfg.Protocol

	for _, port := range cfg.Ports {
		desc := ruleDescription(cfg, port, 255)
		if err := b.upsertRule(proto, port, cidr, desc); err != nil {
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

func (b *HetznerCloud) upsertRule(proto, port, cidr, desc string) error {
	err := b.client.UpsertInbound(proto, port, cidr, desc)
	if err != nil {
		if isHetznerCloudDuplicate(err) || isDuplicate(err) {
			log.Printf("[%s] 防火墙规则已存在，跳过: %s %s %s", b.name, cidr, proto, port)
			return nil
		}
		return fmt.Errorf("set_rules: %w", err)
	}
	log.Printf("[%s] 已添加 Hetzner Cloud 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func (b *HetznerCloud) removeRule(proto, port, cidr string) error {
	err := b.client.RemoveInbound(proto, port, cidr, b.descPrefix)
	if err != nil {
		if isHetznerCloudNotFound(err) || isNotFound(err) {
			log.Printf("[%s] 旧防火墙规则不存在，跳过: %s %s", b.name, cidr, port)
			return nil
		}
		return fmt.Errorf("set_rules: %w", err)
	}
	log.Printf("[%s] 已删除旧 Hetzner Cloud 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func isHetznerCloudDuplicate(err error) bool {
	var apiErr *hetznercloud.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Message + " " + apiErr.Code)
		return strings.Contains(msg, "duplicate") || strings.Contains(msg, "already")
	}
	return false
}

func isHetznerCloudNotFound(err error) bool {
	var apiErr *hetznercloud.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == 404
	}
	return false
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

var _ Backend = (*HetznerCloud)(nil)
