package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/scalewayapi"
)

type ScalewaySG struct {
	name   string
	client *scalewayapi.SecurityGroupClient
}

func NewScalewaySG(t config.Target, _ *config.Config) (*ScalewaySG, error) {
	zone := t.Zone
	if zone == "" {
		zone = t.Region
	}
	return &ScalewaySG{
		name: t.Name,
		client: scalewayapi.NewSecurityGroup(
			t.SecretKey,
			zone,
			t.SecurityGroupID,
		),
	}, nil
}

func (b *ScalewaySG) Name() string { return b.name }

func (b *ScalewaySG) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := strings.ToUpper(cfg.Protocol)

	for _, portStr := range cfg.Ports {
		port, err := scalewayapi.ParsePort(portStr)
		if err != nil {
			return fmt.Errorf("无效端口 %q: %w", portStr, err)
		}
		if err := b.createRule(proto, cidr, port, portStr); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, portStr := range cfg.Ports {
			port, err := scalewayapi.ParsePort(portStr)
			if err != nil {
				return fmt.Errorf("无效端口 %q: %w", portStr, err)
			}
			if err := b.deleteRule(proto, oldCIDR, port, portStr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *ScalewaySG) createRule(proto, cidr string, port uint32, portStr string) error {
	exists, err := b.client.RuleExists(proto, port, cidr)
	if err != nil {
		return fmt.Errorf("ListSecurityGroupRules: %w", err)
	}
	if exists {
		log.Printf("[%s] 安全组规则已存在，跳过: %s %s %s", b.name, cidr, proto, portStr)
		return nil
	}

	err = b.client.CreateInboundAccept(proto, port, cidr)
	if err != nil {
		if isScalewayDuplicate(err) || isDuplicate(err) {
			log.Printf("[%s] 安全组规则已存在，跳过: %s %s %s", b.name, cidr, proto, portStr)
			return nil
		}
		return fmt.Errorf("CreateSecurityGroupRule: %w", err)
	}
	log.Printf("[%s] 已添加 Scaleway 安全组入站规则: %s %s %s", b.name, cidr, proto, portStr)
	return nil
}

func (b *ScalewaySG) deleteRule(proto, cidr string, port uint32, portStr string) error {
	err := b.client.DeleteInboundByMatch(proto, port, cidr)
	if err != nil {
		if isScalewayNotFound(err) || isNotFound(err) {
			log.Printf("[%s] 旧安全组规则不存在，跳过: %s %s", b.name, cidr, portStr)
			return nil
		}
		return fmt.Errorf("DeleteSecurityGroupRule: %w", err)
	}
	log.Printf("[%s] 已删除旧 Scaleway 安全组入站规则: %s %s %s", b.name, cidr, proto, portStr)
	return nil
}

func isScalewayDuplicate(err error) bool {
	var apiErr *scalewayapi.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Message + " " + apiErr.Type)
		return apiErr.Status == 409 ||
			strings.Contains(msg, "already") ||
			strings.Contains(msg, "duplicate") ||
			strings.Contains(msg, "exist")
	}
	return false
}

func isScalewayNotFound(err error) bool {
	var apiErr *scalewayapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status == 404 || apiErr.Type == "not_found"
	}
	return false
}

var _ Backend = (*ScalewaySG)(nil)
