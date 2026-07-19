package backend

import (
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
	"github.com/b1u3h4t/FirewallKeeper/internal/tencentapi"
)

type Lighthouse struct {
	name   string
	client *tencentapi.LighthouseClient
}

func NewLighthouse(t config.Target, _ *config.Config) (*Lighthouse, error) {
	return &Lighthouse{
		name: t.Name,
		client: tencentapi.NewLighthouse(
			t.SecretID,
			t.SecretKey,
			t.Region,
			t.InstanceID,
		),
	}, nil
}

func (b *Lighthouse) Name() string { return b.name }

func (b *Lighthouse) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	portSpec, combined := joinFirewallPorts(cfg.Ports)
	if !combined {
		// Port 字段超长时回退为逐端口（兼容旧行为）
		return b.upsertPerPort(currentIP, oldIP, cfg)
	}

	// 轻量实例防火墙配额有限：先删旧 IP，再加新 IP（一条规则覆盖全部端口）
	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		if err := b.deleteManagedForCIDR(cfg, ip.ToCIDR(*oldIP)); err != nil {
			return err
		}
	}

	if err := b.createRule(cfg, cidr, portSpec); err != nil {
		return err
	}

	// 清理同 IP 下旧的「逐端口」规则，释放配额
	if err := b.deleteLegacyPerPortRules(cfg, cidr, portSpec); err != nil {
		return err
	}
	return nil
}

func (b *Lighthouse) upsertPerPort(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range cfg.Ports {
			if err := b.deleteRuleExact(cfg.Protocol, oldCIDR, port); err != nil {
				return err
			}
		}
	}
	for _, port := range cfg.Ports {
		if err := b.createRule(cfg, cidr, port); err != nil {
			return err
		}
	}
	return nil
}

func (b *Lighthouse) createRule(cfg *config.Config, cidr, port string) error {
	desc := cfg.RuleDescription
	if len(desc) > 64 {
		desc = desc[:64]
	}
	// 合并端口时描述不再带 :port，便于识别本工具规则
	if strings.Contains(port, ",") || strings.Contains(port, "-") {
		// keep desc as-is
	} else if desc != "" {
		desc = ruleDescription(cfg, port, 64)
	}

	err := b.client.CreateRules([]tencentapi.FirewallRule{{
		Protocol:                cfg.Protocol,
		Port:                    port,
		CidrBlock:               cidr,
		Action:                  "ACCEPT",
		FirewallRuleDescription: desc,
	}})
	if err != nil {
		if isDuplicate(err) {
			log.Printf("[%s] 规则已存在，跳过: %s %s %s", b.name, cidr, cfg.Protocol, port)
			return nil
		}
		if isQuotaExceeded(err) {
			freed, cleanErr := b.cleanupStaleManaged(cfg, cidr)
			if cleanErr != nil {
				return fmt.Errorf("CreateFirewallRules: %w (清理旧规则失败: %v)", err, cleanErr)
			}
			if freed == 0 {
				return fmt.Errorf("CreateFirewallRules: %w", err)
			}
			log.Printf("[%s] 防火墙规则配额已满，已清理 %d 条本工具管理的过期规则，重试添加", b.name, freed)
			return b.createRuleOnce(cfg, cidr, port, desc)
		}
		return fmt.Errorf("CreateFirewallRules: %w", err)
	}
	log.Printf("[%s] 已添加轻量防火墙规则: %s %s %s", b.name, cidr, cfg.Protocol, port)
	return nil
}

func (b *Lighthouse) createRuleOnce(cfg *config.Config, cidr, port, desc string) error {
	err := b.client.CreateRules([]tencentapi.FirewallRule{{
		Protocol:                cfg.Protocol,
		Port:                    port,
		CidrBlock:               cidr,
		Action:                  "ACCEPT",
		FirewallRuleDescription: desc,
	}})
	if err != nil {
		if isDuplicate(err) {
			log.Printf("[%s] 规则已存在，跳过: %s %s %s", b.name, cidr, cfg.Protocol, port)
			return nil
		}
		return fmt.Errorf("CreateFirewallRules: %w", err)
	}
	log.Printf("[%s] 已添加轻量防火墙规则: %s %s %s", b.name, cidr, cfg.Protocol, port)
	return nil
}

func (b *Lighthouse) deleteRuleExact(protocol, cidr, port string) error {
	err := b.client.DeleteRules([]tencentapi.FirewallRule{{
		Protocol:  protocol,
		Port:      port,
		CidrBlock: cidr,
		Action:    "ACCEPT",
	}})
	if err != nil {
		if isNotFound(err) {
			log.Printf("[%s] 旧规则不存在，跳过删除: %s %s", b.name, cidr, port)
			return nil
		}
		return fmt.Errorf("DeleteFirewallRules: %w", err)
	}
	log.Printf("[%s] 已删除旧轻量防火墙规则: %s %s %s", b.name, cidr, protocol, port)
	return nil
}

func (b *Lighthouse) deleteManagedForCIDR(cfg *config.Config, cidr string) error {
	rules, err := b.client.DescribeRules()
	if err != nil {
		return fmt.Errorf("DescribeFirewallRules: %w", err)
	}
	prefix := cfg.RuleDescription
	var toDelete []tencentapi.FirewallRule
	for _, r := range rules {
		if prefix != "" && !strings.HasPrefix(r.FirewallRuleDescription, prefix) {
			continue
		}
		if !strings.EqualFold(r.Action, "ACCEPT") || r.CidrBlock != cidr {
			continue
		}
		toDelete = append(toDelete, tencentapi.FirewallRule{
			Protocol:  r.Protocol,
			Port:      r.Port,
			CidrBlock: r.CidrBlock,
			Action:    r.Action,
		})
	}
	if len(toDelete) == 0 {
		return nil
	}
	if err := b.client.DeleteRules(toDelete); err != nil {
		return fmt.Errorf("DeleteFirewallRules: %w", err)
	}
	for _, r := range toDelete {
		log.Printf("[%s] 已删除旧轻量防火墙规则: %s %s %s", b.name, r.CidrBlock, r.Protocol, r.Port)
	}
	return nil
}

func (b *Lighthouse) deleteLegacyPerPortRules(cfg *config.Config, cidr, keepPort string) error {
	rules, err := b.client.DescribeRules()
	if err != nil {
		return fmt.Errorf("DescribeFirewallRules: %w", err)
	}
	prefix := cfg.RuleDescription
	var toDelete []tencentapi.FirewallRule
	for _, r := range rules {
		if prefix != "" && !strings.HasPrefix(r.FirewallRuleDescription, prefix) {
			continue
		}
		if !strings.EqualFold(r.Action, "ACCEPT") || r.CidrBlock != cidr {
			continue
		}
		if sameFirewallPorts(r.Port, keepPort) {
			continue
		}
		toDelete = append(toDelete, tencentapi.FirewallRule{
			Protocol:  r.Protocol,
			Port:      r.Port,
			CidrBlock: r.CidrBlock,
			Action:    r.Action,
		})
	}
	if len(toDelete) == 0 {
		return nil
	}
	if err := b.client.DeleteRules(toDelete); err != nil {
		return fmt.Errorf("DeleteFirewallRules: %w", err)
	}
	for _, r := range toDelete {
		log.Printf("[%s] 已清理同 IP 旧逐端口规则: %s %s %s", b.name, r.CidrBlock, r.Protocol, r.Port)
	}
	return nil
}

// cleanupStaleManaged 删除本工具管理的、非当前 IP 的规则，释放配额。
func (b *Lighthouse) cleanupStaleManaged(cfg *config.Config, keepCIDR string) (int, error) {
	rules, err := b.client.DescribeRules()
	if err != nil {
		return 0, fmt.Errorf("DescribeFirewallRules: %w", err)
	}

	prefix := cfg.RuleDescription
	var stale []tencentapi.FirewallRule
	for _, r := range rules {
		if prefix != "" && !strings.HasPrefix(r.FirewallRuleDescription, prefix) {
			continue
		}
		if strings.EqualFold(r.Action, "ACCEPT") && r.CidrBlock != keepCIDR {
			stale = append(stale, tencentapi.FirewallRule{
				Protocol:  r.Protocol,
				Port:      r.Port,
				CidrBlock: r.CidrBlock,
				Action:    r.Action,
			})
		}
	}
	if len(stale) == 0 {
		return 0, nil
	}
	if err := b.client.DeleteRules(stale); err != nil {
		return 0, err
	}
	for _, r := range stale {
		log.Printf("[%s] 已清理过期规则以释放配额: %s %s %s", b.name, r.CidrBlock, r.Protocol, r.Port)
	}
	return len(stale), nil
}

var _ Backend = (*Lighthouse)(nil)
