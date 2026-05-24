package backend

import (
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/tencentapi"
)

type CVM struct {
	client *tencentapi.VPCClient
}

func NewCVM(cfg *config.Config) (*CVM, error) {
	return &CVM{
		client: tencentapi.NewVPC(
			cfg.Tencent.SecretID,
			cfg.Tencent.SecretKey,
			cfg.Tencent.Region,
			cfg.SecurityGroupID,
		),
	}, nil
}

func (b *CVM) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	for _, port := range cfg.Ports {
		if err := b.createIngress(cfg, cidr, port); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range cfg.Ports {
			if err := b.deleteIngress(cfg, oldCIDR, port); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *CVM) createIngress(cfg *config.Config, cidr, port string) error {
	err := b.client.CreateIngress([]tencentapi.SecurityGroupPolicy{{
		Protocol:          strings.ToLower(cfg.Protocol),
		Port:              port,
		CidrBlock:         cidr,
		Action:            "ACCEPT",
		PolicyDescription: ruleDescription(cfg, port, 100),
	}})
	if err != nil {
		if isDuplicate(err) {
			log.Printf("安全组规则已存在，跳过: %s %s %s", cidr, cfg.Protocol, port)
			return nil
		}
		return fmt.Errorf("CreateSecurityGroupPolicies: %w", err)
	}
	log.Printf("已添加安全组入站规则: %s %s %s", cidr, cfg.Protocol, port)
	return nil
}

func (b *CVM) deleteIngress(cfg *config.Config, cidr, port string) error {
	err := b.client.DeleteIngress([]tencentapi.SecurityGroupPolicy{{
		Protocol:  strings.ToLower(cfg.Protocol),
		Port:      port,
		CidrBlock: cidr,
		Action:    "ACCEPT",
	}})
	if err != nil {
		if isNotFound(err) {
			log.Printf("旧安全组规则不存在，跳过: %s %s", cidr, port)
			return nil
		}
		return fmt.Errorf("DeleteSecurityGroupPolicies: %w", err)
	}
	log.Printf("已删除旧安全组入站规则: %s %s %s", cidr, cfg.Protocol, port)
	return nil
}

var _ Backend = (*CVM)(nil)
