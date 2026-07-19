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
	name   string
	client *tencentapi.VPCClient
}

func NewCVM(t config.Target, _ *config.Config) (*CVM, error) {
	return &CVM{
		name: t.Name,
		client: tencentapi.NewVPC(
			t.SecretID,
			t.SecretKey,
			t.Region,
			t.SecurityGroupID,
		),
	}, nil
}

func (b *CVM) Name() string { return b.name }

func (b *CVM) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	portSpec, ok := joinFirewallPorts(cfg.Ports)
	ports := cfg.Ports
	if ok {
		ports = []string{portSpec}
	}

	// 先删旧 IP，再加新规则，降低安全组策略条数触顶概率
	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range ports {
			if err := b.deleteIngress(cfg, oldCIDR, port); err != nil {
				return err
			}
		}
		// 合并模式时同时清理旧逐端口规则
		if ok {
			for _, port := range cfg.Ports {
				_ = b.deleteIngress(cfg, oldCIDR, port)
			}
		}
	}

	for _, port := range ports {
		if err := b.createIngress(cfg, cidr, port); err != nil {
			return err
		}
	}
	return nil
}

func (b *CVM) createIngress(cfg *config.Config, cidr, port string) error {
	desc := ruleDescription(cfg, port, 100)
	if strings.Contains(port, ",") || strings.Contains(port, "-") {
		desc = cfg.RuleDescription
		if len(desc) > 100 {
			desc = desc[:100]
		}
	}
	err := b.client.CreateIngress([]tencentapi.SecurityGroupPolicy{{
		Protocol:          strings.ToLower(cfg.Protocol),
		Port:              port,
		CidrBlock:         cidr,
		Action:            "ACCEPT",
		PolicyDescription: desc,
	}})
	if err != nil {
		if isDuplicate(err) {
			log.Printf("[%s] 安全组规则已存在，跳过: %s %s %s", b.name, cidr, cfg.Protocol, port)
			return nil
		}
		return fmt.Errorf("CreateSecurityGroupPolicies: %w", err)
	}
	log.Printf("[%s] 已添加安全组入站规则: %s %s %s", b.name, cidr, cfg.Protocol, port)
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
			log.Printf("[%s] 旧安全组规则不存在，跳过: %s %s", b.name, cidr, port)
			return nil
		}
		return fmt.Errorf("DeleteSecurityGroupPolicies: %w", err)
	}
	log.Printf("[%s] 已删除旧安全组入站规则: %s %s %s", b.name, cidr, cfg.Protocol, port)
	return nil
}

var _ Backend = (*CVM)(nil)
