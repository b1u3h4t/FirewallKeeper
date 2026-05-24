package tencentapi

const (
	vpcHost    = "vpc.tencentcloudapi.com"
	vpcVersion = "2017-03-12"
)

type SecurityGroupPolicy struct {
	Protocol          string `json:"Protocol"`
	Port              string `json:"Port"`
	CidrBlock         string `json:"CidrBlock"`
	Action            string `json:"Action"`
	PolicyDescription string `json:"PolicyDescription,omitempty"`
}

type VPCClient struct {
	api             *Client
	securityGroupID string
}

func NewVPC(secretID, secretKey, region, securityGroupID string) *VPCClient {
	return &VPCClient{
		api: NewClient(
			secretID, secretKey, region,
			"vpc", vpcHost, vpcVersion,
		),
		securityGroupID: securityGroupID,
	}
}

func (c *VPCClient) CreateIngress(policies []SecurityGroupPolicy) error {
	return c.api.Do("CreateSecurityGroupPolicies", map[string]any{
		"SecurityGroupId": c.securityGroupID,
		"SecurityGroupPolicySet": map[string]any{
			"Ingress": policies,
		},
	})
}

func (c *VPCClient) DeleteIngress(policies []SecurityGroupPolicy) error {
	return c.api.Do("DeleteSecurityGroupPolicies", map[string]any{
		"SecurityGroupId": c.securityGroupID,
		"SecurityGroupPolicySet": map[string]any{
			"Ingress": policies,
		},
	})
}
