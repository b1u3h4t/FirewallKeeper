package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/netcupapi"
)

type NetcupFirewall struct {
	name       string
	client     *netcupapi.FirewallPolicyClient
	api        *netcupapi.Client
	serverID   int
	interfaceMAC string
	descPrefix string
}

func NewNetcupFirewall(t config.Target, cfg *config.Config) (*NetcupFirewall, error) {
	policyIDStr := firstNonEmptyStr(t.FirewallID, t.SecurityGroupID)
	policyID, err := netcupapi.ParseIntID(policyIDStr, "firewall_policy_id")
	if err != nil {
		return nil, err
	}

	refreshToken := t.RefreshToken
	accessToken := t.APIToken
	api := netcupapi.NewClient(refreshToken, accessToken, t.Endpoint)

	userID := 0
	if strings.TrimSpace(t.UserID) != "" {
		userID, err = netcupapi.ParseIntID(t.UserID, "user_id")
		if err != nil {
			return nil, err
		}
	} else {
		userID, err = api.CurrentUserID()
		if err != nil {
			return nil, fmt.Errorf("获取 user_id: %w（请在配置中填写 user_id）", err)
		}
	}

	b := &NetcupFirewall{
		name:       t.Name,
		api:        api,
		client:     netcupapi.NewFirewallPolicy(refreshToken, accessToken, t.Endpoint, userID, policyID),
		descPrefix: cfg.RuleDescription,
	}

	if t.InstanceID != "" {
		b.serverID, err = netcupapi.ParseIntID(t.InstanceID, "server_id")
		if err != nil {
			return nil, err
		}
	}
	b.interfaceMAC = strings.TrimSpace(t.InterfaceMAC)
	return b, nil
}

func (b *NetcupFirewall) Name() string { return b.name }

func (b *NetcupFirewall) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := cfg.Protocol

	for _, portStr := range cfg.Ports {
		desc := ruleDescription(cfg, portStr, 255)
		if err := b.upsertRule(proto, portStr, cidr, desc); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, portStr := range cfg.Ports {
			if err := b.removeRule(proto, portStr, oldCIDR); err != nil {
				return err
			}
		}
	}

	if err := b.reapplyIfConfigured(); err != nil {
		return err
	}
	return nil
}

func (b *NetcupFirewall) upsertRule(proto, port, cidr, desc string) error {
	err := b.client.UpsertIngress(proto, port, cidr, desc)
	if err != nil {
		if isNetcupDuplicate(err) || isDuplicate(err) {
			log.Printf("[%s] 防火墙规则已存在，跳过: %s %s %s", b.name, cidr, proto, port)
			return nil
		}
		return fmt.Errorf("update firewall policy: %w", err)
	}
	log.Printf("[%s] 已添加 Netcup SCP 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func (b *NetcupFirewall) removeRule(proto, port, cidr string) error {
	err := b.client.RemoveIngress(proto, port, cidr, b.descPrefix)
	if err != nil {
		if isNetcupNotFound(err) || isNotFound(err) {
			log.Printf("[%s] 旧防火墙规则不存在，跳过: %s %s", b.name, cidr, port)
			return nil
		}
		return fmt.Errorf("update firewall policy: %w", err)
	}
	log.Printf("[%s] 已删除旧 Netcup SCP 防火墙规则: %s %s %s", b.name, cidr, proto, port)
	return nil
}

func (b *NetcupFirewall) reapplyIfConfigured() error {
	if b.serverID == 0 {
		return nil
	}
	mac := b.interfaceMAC
	if mac == "" {
		var err error
		mac, err = netcupapi.FirstInterfaceMAC(b.api, b.serverID)
		if err != nil {
			return fmt.Errorf("获取 interface_mac: %w", err)
		}
	}
	if err := netcupapi.ReapplyServerFirewall(b.api, b.serverID, mac); err != nil {
		return fmt.Errorf("firewall reapply: %w", err)
	}
	log.Printf("[%s] 已在服务器 %d 网卡 %s 上重新应用防火墙", b.name, b.serverID, mac)
	return nil
}

func isNetcupDuplicate(err error) bool {
	var apiErr *netcupapi.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Code + " " + apiErr.Message)
		return strings.Contains(msg, "duplicate") || strings.Contains(msg, "already") || strings.Contains(msg, "exist")
	}
	return false
}

func isNetcupNotFound(err error) bool {
	var apiErr *netcupapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == 404 || apiErr.Code == "not_found"
	}
	return false
}

var _ Backend = (*NetcupFirewall)(nil)
