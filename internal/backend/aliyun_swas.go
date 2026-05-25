package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/aliyunapi"
	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
)

type AliyunSWAS struct {
	client *aliyunapi.SWASClient
}

func NewAliyunSWAS(cfg *config.Config) (*AliyunSWAS, error) {
	return &AliyunSWAS{
		client: aliyunapi.NewSWAS(
			cfg.Aliyun.AccessKeyID,
			cfg.Aliyun.AccessKeySecret,
			cfg.Aliyun.Region,
			cfg.Aliyun.Endpoint,
			cfg.AliyunSWASInstanceID,
		),
	}, nil
}

func (b *AliyunSWAS) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := strings.ToUpper(cfg.Protocol)

	for _, port := range cfg.Ports {
		if err := b.createRule(cfg, proto, cidr, port); err != nil {
			return err
		}
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, port := range cfg.Ports {
			if err := b.deleteRule(proto, oldCIDR, port); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *AliyunSWAS) createRule(cfg *config.Config, proto, cidr, port string) error {
	remark := ruleDescription(cfg, port, 64)
	err := b.client.CreateRules(proto, port, cidr, remark)
	if err != nil {
		if isAliyunDuplicate(err) {
			log.Printf("规则已存在，跳过: %s %s %s", cidr, proto, port)
			return nil
		}
		return fmt.Errorf("CreateFirewallRules: %w", err)
	}
	log.Printf("已添加阿里云 SWAS 防火墙规则: %s %s %s", cidr, proto, port)
	return nil
}

func (b *AliyunSWAS) deleteRule(proto, cidr, port string) error {
	err := b.client.DeleteRulesByMatch(proto, port, cidr)
	if err != nil {
		if isAliyunNotFound(err) {
			log.Printf("旧规则不存在，跳过删除: %s %s", cidr, port)
			return nil
		}
		return fmt.Errorf("DeleteFirewallRules: %w", err)
	}
	log.Printf("已删除旧阿里云 SWAS 防火墙规则: %s %s %s", cidr, proto, port)
	return nil
}

func isAliyunDuplicate(err error) bool {
	var apiErr *aliyunapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "FirewallRuleAlreadyExist"
	}
	return isDuplicate(err)
}

func isAliyunNotFound(err error) bool {
	var apiErr *aliyunapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == "RuleNotFound" || apiErr.Code == "InvalidRuleIds.NotFound"
	}
	return isNotFound(err)
}

var _ Backend = (*AliyunSWAS)(nil)
