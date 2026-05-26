package volcapi

import (
	"fmt"
	"strconv"
	"strings"
)

type SecurityGroupClient struct {
	api             *Client
	securityGroupID string
}

func NewSecurityGroup(accessKeyID, accessKeySecret, region, endpoint, securityGroupID string) *SecurityGroupClient {
	return &SecurityGroupClient{
		api:             NewVPCClient(accessKeyID, accessKeySecret, region, endpoint),
		securityGroupID: securityGroupID,
	}
}

func (c *SecurityGroupClient) AuthorizeIngress(proto string, portStart, portEnd int, cidr, description string) error {
	params := map[string]string{
		"SecurityGroupId": c.securityGroupID,
		"Protocol":        normalizeProtocol(proto),
		"PortStart":       strconv.Itoa(portStart),
		"PortEnd":         strconv.Itoa(portEnd),
		"CidrIp":          cidr,
		"Policy":          "accept",
	}
	if description != "" {
		params["Description"] = description
	}
	_, err := c.api.Do("AuthorizeSecurityGroupIngress", params)
	return err
}

func (c *SecurityGroupClient) RevokeIngress(proto string, portStart, portEnd int, cidr string) error {
	params := map[string]string{
		"SecurityGroupId": c.securityGroupID,
		"Protocol":        normalizeProtocol(proto),
		"PortStart":       strconv.Itoa(portStart),
		"PortEnd":         strconv.Itoa(portEnd),
		"CidrIp":          cidr,
	}
	_, err := c.api.Do("RevokeSecurityGroupIngress", params)
	return err
}

func normalizeProtocol(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	switch p {
	case "tcp", "udp", "icmp", "icmpv6", "all":
		return p
	default:
		return "tcp"
	}
}

func ParsePort(port string) (start, end int, err error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, 0, fmt.Errorf("empty port")
	}
	if strings.Contains(port, "-") {
		parts := strings.SplitN(port, "-", 2)
		start, err = strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return 0, 0, err
		}
		end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		return start, end, err
	}
	n, err := strconv.Atoi(port)
	return n, n, err
}
