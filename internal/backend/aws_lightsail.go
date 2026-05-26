package backend

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/b1u3h4t/FirewallKeeper/internal/awsapi"
	"github.com/b1u3h4t/FirewallKeeper/internal/config"
	"github.com/b1u3h4t/FirewallKeeper/internal/ip"
)

type AWSLightsail struct {
	name         string
	client       *awsapi.LightsailClient
	instanceName string
}

func NewAWSLightsail(t config.Target, _ *config.Config) (*AWSLightsail, error) {
	instanceName := firstNonEmptyStr(t.InstanceName, t.InstanceID)
	if instanceName == "" {
		return nil, fmt.Errorf("需要 instance_name 或 instance_id（Lightsail 实例名称）")
	}
	return &AWSLightsail{
		name:         t.Name,
		instanceName: instanceName,
		client: awsapi.NewLightsail(
			t.AccessKeyID,
			t.AccessKeySecret,
			t.Region,
		),
	}, nil
}

func (b *AWSLightsail) Name() string { return b.name }

func (b *AWSLightsail) UpsertWhitelist(currentIP string, oldIP *string, cfg *config.Config) error {
	cidr := ip.ToCIDR(currentIP)
	proto := cfg.Protocol

	states, err := b.client.GetPortStates(b.instanceName)
	if err != nil {
		return fmt.Errorf("GetInstancePortStates: %w", err)
	}

	for _, portStr := range cfg.Ports {
		port, err := awsapi.ParsePort(portStr)
		if err != nil {
			return fmt.Errorf("无效端口 %q: %w", portStr, err)
		}
		if b.client.PortExists(states, proto, port, cidr) {
			log.Printf("[%s] 防火墙规则已存在，跳过: %s %s %d", b.name, cidr, proto, port)
			continue
		}
		info := awsapi.PortInfo{
			FromPort: port,
			ToPort:   port,
			Protocol: strings.ToLower(proto),
			CIDRs:    []string{cidr},
		}
		if err := b.client.OpenPort(b.instanceName, info); err != nil {
			if isDuplicate(err) {
				log.Printf("[%s] 防火墙规则已存在，跳过: %s %s %d", b.name, cidr, proto, port)
				continue
			}
			return fmt.Errorf("OpenInstancePublicPorts: %w", err)
		}
		log.Printf("[%s] 已添加 AWS Lightsail 防火墙规则: %s %s %d", b.name, cidr, proto, port)
	}

	if cfg.RemoveOldIP && oldIP != nil && *oldIP != "" && *oldIP != currentIP {
		oldCIDR := ip.ToCIDR(*oldIP)
		for _, portStr := range cfg.Ports {
			port, err := awsapi.ParsePort(portStr)
			if err != nil {
				return fmt.Errorf("无效端口 %q: %w", portStr, err)
			}
			if err := b.closePort(proto, port, oldCIDR, portStr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *AWSLightsail) closePort(proto string, port int, cidr, portStr string) error {
	info := awsapi.PortInfo{
		FromPort: port,
		ToPort:   port,
		Protocol: strings.ToLower(proto),
		CIDRs:    []string{cidr},
	}
	err := b.client.ClosePort(b.instanceName, info)
	if err != nil {
		if isAWSNotFound(err) || isNotFound(err) {
			log.Printf("[%s] 旧防火墙规则不存在，跳过: %s %s", b.name, cidr, portStr)
			return nil
		}
		return fmt.Errorf("CloseInstancePublicPorts: %w", err)
	}
	log.Printf("[%s] 已删除旧 AWS Lightsail 防火墙规则: %s %s %d", b.name, cidr, proto, port)
	return nil
}

func isAWSNotFound(err error) bool {
	var apiErr *awsapi.APIError
	if errors.As(err, &apiErr) {
		msg := strings.ToLower(apiErr.Code + " " + apiErr.Message)
		return strings.Contains(msg, "notfound") || strings.Contains(msg, "not found")
	}
	return false
}

var _ Backend = (*AWSLightsail)(nil)
