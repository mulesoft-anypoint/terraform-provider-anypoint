package anypoint

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

var DATASOURCES_MAP = map[string]*schema.Resource{
	"anypoint_vpcs":                                  dataSourceVPCs(),
	"anypoint_vpc":                                   dataSourceVPC(),
	"anypoint_vpn":                                   dataSourceVPN(),
	"anypoint_bg":                                    dataSourceBG(),
	"anypoint_roles":                                 dataSourceRoles(),
	"anypoint_rolegroup":                             dataSourceRoleGroup(),
	"anypoint_rolegroups":                            dataSourceRoleGroups(),
	"anypoint_users":                                 dataSourceUsers(),
	"anypoint_user":                                  dataSourceUser(),
	"anypoint_env":                                   dataSourceENV(),
	"anypoint_user_rolegroup":                        dataSourceUserRolegroup(),
	"anypoint_user_rolegroups":                       dataSourceUserRolegroups(),
	"anypoint_team":                                  dataSourceTeam(),
	"anypoint_teams":                                 dataSourceTeams(),
	"anypoint_team_roles":                            dataSourceTeamRoles(),
	"anypoint_team_members":                          dataSourceTeamMembers(),
	"anypoint_team_group_mappings":                   dataSourceTeamGroupMappings(),
	"anypoint_dlb":                                   dataSourceDLB(),
	"anypoint_dlbs":                                  dataSourceDLBs(),
	"anypoint_idp":                                   dataSourceIDP(),
	"anypoint_idps":                                  dataSourceIDPs(),
	"anypoint_connected_app":                         dataSourceConnectedApp(),
	"anypoint_connected_apps":                        dataSourceConnectedApps(),
	"anypoint_amq":                                   dataSourceAMQ(),
	"anypoint_ame":                                   dataSourceAME(),
	"anypoint_apim":                                  dataSourceApim(),
	"anypoint_apim_instance":                         dataSourceApimInstance(),
	"anypoint_apim_instance_policy":                  dataSourceApimInstancePolicy(),
	"anypoint_apim_instance_policies":                dataSourceApimInstancePolicies(),
	"anypoint_apim_instance_upstreams":               dataSourceApimInstanceUpstreams(),
	"anypoint_flexgateway_target":                    dataSourceFlexGatewayTarget(),
	"anypoint_flexgateway_targets":                   dataSourceFlexGatewayTargets(),
	"anypoint_flexgateway_registration_token":        dataSourceFlexGatewayRegistrationToken(),
	"anypoint_secretgroups":                          dataSourceSecretGroups(),
	"anypoint_secretgroup":                           dataSourceSecretGroup(),
	"anypoint_secretgroup_keystores":                 dataSourceSecretGroupKeystores(),
	"anypoint_secretgroup_keystore":                  dataSourceSecretGroupKeystore(),
	"anypoint_secretgroup_truststores":               dataSourceSecretGroupTruststores(),
	"anypoint_secretgroup_truststore":                dataSourceSecretGroupTruststore(),
	"anypoint_secretgroup_certificates":              dataSourceSecretGroupCertificates(),
	"anypoint_secretgroup_certificate":               dataSourceSecretGroupCertificate(),
	"anypoint_secretgroup_tlscontexts":               dataSourceSecretGroupTlsContexts(),
	"anypoint_secretgroup_tlscontext_flexgateway":    dataSourceSecretGroupTlsContextFG(),
	"anypoint_secretgroup_tlscontext_securityfabric": dataSourceSecretGroupTlsContextSF(),
	"anypoint_secretgroup_tlscontext_mule":           dataSourceSecretGroupTlsContextMule(),
	"anypoint_secretgroup_crldistrib_cfgs_list":      dataSourceSecretGroupCrlDistribCfgsList(),
	"anypoint_secretgroup_crldistrib_cfgs":           dataSourceSecretGroupCrlDistribCfgs(),
	"anypoint_exchange_policy_templates":             dataSourceExchangePolicyTemplates(),
	"anypoint_exchange_policy_template":              dataSourceExchangePolicyTemplate(),
	"anypoint_fabrics_list":                          dataSourceFabricsCollection(),
	"anypoint_fabrics":                               dataSourceFabrics(),
	"anypoint_fabrics_associations":                  dataSourceFabricsAssociations(),
	"anypoint_fabrics_helm_repo":                     dataSourceFabricsHelmRepoProps(),
	"anypoint_fabrics_health":                        dataSourceFabricsHealth(),
	"anypoint_app_deployment_v2":                     dataSourceAppDeploymentV2(),
	"anypoint_app_deployments_v2":                    dataSourceAppDeploymentsV2(),
	"anypoint_private_space":                         dataSourcePrivateSpace(),
	"anypoint_private_spaces":                        dataSourcePrivateSpaces(),
	"anypoint_private_space_tlscontext":              dataSourcePrivateSpaceTlsContext(),
	"anypoint_private_space_tlscontexts":             dataSourcePrivateSpaceTlsContexts(),
	"anypoint_private_space_iam_roles":               dataSourcePrivateSpaceIamRoles(),
}
