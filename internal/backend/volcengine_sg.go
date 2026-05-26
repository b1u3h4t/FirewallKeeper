package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/volcapi"
)

type VolcengineSG struct {
	name   string
	client *volcapi.SecurityGroupClient
}

func NewVolcengineSG(t config.Target, cfg *config.Config) (*VolcengineSG, error) {
	return &VolcengineSG{
		name: t.Name,
		client: volcapi.NewSecurityGroup(
			t.AccessKeyID,
			t.AccessKeySecret,
			t.Region,
			t.Endpoint,
			t.SecurityGroupID,
		),
	}, nil
}

func (b *VolcengineSG) Name() string { return b.name }

func (b *VolcengineSG) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := cfg.Protocol

	for _, portStr := range cfg.Ports {
		portStart, portEnd, err := volcapi.ParsePort(portStr)
		if err != nil {
			return fmt.Errorf("无效端口 %q: %w", portStr, err)
		}
		desc := ruleDescription(cfg, portStr, 255)
		if err := b.authorize(proto, portStart, portEnd, cidr, desc, portStr); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, portStr := range cfg.Ports {
			portStart, portEnd, err := volcapi.ParsePort(portStr)
			if err != nil {
				return fmt.Errorf("无效端口 %q: %w", portStr, err)
			}
			if err := b.revoke(proto, portStart, portEnd, oldCIDR, portStr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *VolcengineSG) authorize(proto string, portStart, portEnd int, cidr, desc, portStr string) error {
	err := b.client.AuthorizeIngress(proto, portStart, portEnd, cidr, desc)
	if err != nil {
		if isVolcDuplicate(err) || isDuplicate(err) {
			log.Printf("[%s] 安全组规则已存在，跳过: %s %s %s", b.name, cidr, proto, portStr)
			return nil
		}
		return fmt.Errorf("AuthorizeSecurityGroupIngress: %w", err)
	}
	log.Printf("[%s] 已添加火山引擎安全组入站规则: %s %s %s", b.name, cidr, proto, portStr)
	return nil
}

func (b *VolcengineSG) revoke(proto string, portStart, portEnd int, cidr, portStr string) error {
	err := b.client.RevokeIngress(proto, portStart, portEnd, cidr)
	if err != nil {
		if isVolcNotFound(err) || isNotFound(err) {
			log.Printf("[%s] 旧安全组规则不存在，跳过: %s %s", b.name, cidr, portStr)
			return nil
		}
		return fmt.Errorf("RevokeSecurityGroupIngress: %w", err)
	}
	log.Printf("[%s] 已删除旧火山引擎安全组入站规则: %s %s %s", b.name, cidr, proto, portStr)
	return nil
}

func isVolcDuplicate(err error) bool {
	var apiErr *volcapi.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Code + " " + apiErr.Message)
		return strings.Contains(msg, "duplicate") ||
			strings.Contains(msg, "already") ||
			strings.Contains(msg, "exist")
	}
	return false
}

func isVolcNotFound(err error) bool {
	var apiErr *volcapi.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Code + " " + apiErr.Message)
		return strings.Contains(msg, "notfound") || strings.Contains(msg, "not found")
	}
	return false
}

var _ Backend = (*VolcengineSG)(nil)
