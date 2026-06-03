# Generic API Manager policy resource — works for any policy template.
# Validates `configuration_data` against the policy's published JSON Schema
# at plan time, so misconfigurations surface before `terraform apply`.

# Example 1: simple inbound client-id-enforcement policy.
resource "anypoint_apim_policy" "client_id_enf" {
  org_id  = var.root_org
  env_id  = var.env_id
  apim_id = anypoint_apim_mule4.api.id

  asset_group_id = "68ef9520-24e9-4cf2-b2f5-620025690913"
  asset_id       = "client-id-enforcement"
  asset_version  = "1.3.3"

  configuration_data = jsonencode({
    credentialsOriginHasHttpBasicAuthenticationHeader = "customExpression"
    clientIdExpression                                = "#[attributes.headers['client_id']]"
    clientSecretExpression                            = "#[attributes.headers['client_secret']]"
  })
}

# Example 2: outbound credential-injection-oauth2-obo policy. `injection_point`
# selects the outbound endpoint family and `upstream_id` binds the policy to
# a specific api instance upstream.
data "anypoint_apim_instance_upstreams" "api_upstreams" {
  id     = anypoint_apim_mule4.api.id
  org_id = var.root_org
  env_id = var.env_id
}

resource "anypoint_apim_policy" "obo" {
  org_id  = var.root_org
  env_id  = var.env_id
  apim_id = anypoint_apim_mule4.api.id

  asset_group_id  = "68ef9520-24e9-4cf2-b2f5-620025690913"
  asset_id        = "credential-injection-oauth2-obo"
  asset_version   = "1.1.1"
  injection_point = "outbound"
  upstream_id     = data.anypoint_apim_instance_upstreams.api_upstreams.upstreams[0].id

  configuration_data = jsonencode({
    flow             = "microsoft-entra-obo"
    clientId         = var.mule_obo_client_id
    clientSecret     = var.mule_obo_client_secret
    tokenEndpoint    = var.token_exchange_endpoint
    scope            = var.api_scope
    timeout          = 10000
    distributed      = false
    cibaEnabled      = false
    subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
    targetType       = "audience"
  })
}

# Example 3: compose with the drift data source for CI gates.
data "anypoint_exchange_asset_version_drift" "obo" {
  org_id           = var.root_org
  asset_group_id   = anypoint_apim_policy.obo.asset_group_id
  asset_id         = anypoint_apim_policy.obo.asset_id
  declared_version = anypoint_apim_policy.obo.asset_version
}

output "obo_drift_severity" {
  value = data.anypoint_exchange_asset_version_drift.obo.drift_severity
}
