---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "anypoint_apim_policy_jwt_validation Resource - terraform-provider-anypoint"
subcategory: ""
description: |-
  Create and Manage an API Manager Instance Policy of type jwt-validation.
---

# anypoint_apim_policy_jwt_validation (Resource)

Create and Manage an API Manager Instance Policy of type jwt-validation.

## Example Usage

```terraform
resource "anypoint_apim_policy_jwt_validation" "policy01" {
  org_id = var.root_org
  env_id = var.env_id
  apim_id = anypoint_apim_mule4.api.id
  disabled = true
  asset_version = "1.3.2"
  configuration_data {
    jwt_origin          = "httpBearerAuthenticationHeader"
    signing_method      = "rsa"
    signing_key_length  = 512
    jwt_key_origin      = "text"
    text_key            = "your-(256|384|512)-bit-secret"
  }
  pointcut_data {
    method_regex = ["GET", "POST"]
    uri_template_regex = "/api/v1/.*"
  }
  pointcut_data {
    method_regex = ["PUT"]
    uri_template_regex = "/api/v1/.*"
  }
}

resource "anypoint_apim_policy_jwt_validation" "policy02" {
  org_id = var.root_org
  env_id = var.env_id
  apim_id = anypoint_apim_mule4.api.id
  disabled = true
  asset_version = "1.3.2"
  configuration_data {
    jwt_origin = "httpBearerAuthenticationHeader"
    signing_method = "rsa"
    signing_key_length = 512
    jwt_key_origin = "jwks"
    jwks_url = "http://your-jwks-service.example:80/base/path"
    jwks_service_time_to_live = 60
    jwks_service_connection_timeout = 1000
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `apim_id` (String) The api manager instance id where the api instance is defined.
- `configuration_data` (Block List, Min: 1, Max: 1) The policy configuration data (see [below for nested schema](#nestedblock--configuration_data))
- `env_id` (String) The environment id where api instance is defined.
- `org_id` (String) The organization id where the api instance is defined.

### Optional

- `asset_group_id` (String) The policy template group id in anypoint exchange. Don't change unless mulesoft has renamed the policy group id.
- `asset_id` (String) The policy template id in anypoint exchange. Don't change unless mulesoft has renamed the policy asset id.
- `asset_version` (String) the policy template version in anypoint exchange.
- `disabled` (Boolean) Whether the policy is disabled.
- `last_updated` (String) The last time this resource has been updated locally.
- `pointcut_data` (Block List) The Method & resource conditions (see [below for nested schema](#nestedblock--pointcut_data))

### Read-Only

- `audit` (Map of String) The instance's auditing data
- `id` (String) The policy's unique id
- `master_organization_id` (String) The organization id where the api instance is defined.
- `order` (Number) The policy order.
- `policy_template_id` (String) The policy template id

<a id="nestedblock--configuration_data"></a>
### Nested Schema for `configuration_data`

Required:

- `jwt_key_origin` (String) Origin of the JWT Key. The JWKS option is only supported if the JWT Signing Method was set to RSA or ES.
							Ignore this field if the JWT Signing Method was set to None.
- `jwt_origin` (String) Whether to use custom header or to use bearer authentication header.
							Values can be either "httpBearerAuthenticationHeader" or "customExpression".
							In the case of using "httpBearerAuthenticationHeader", you don't need to supply jwt_expression.
- `signing_method` (String) Specifies the method to be used by the policy to decode the JWT.
							Values can be either "rsa", "hmac", "es" and "none".

Optional:

- `client_id_expression` (String) Expression to obtain the Client ID from the request in order to validate it.
- `jwks_service_connection_timeout` (Number) Timeout specification, in milliseconds, when reaching the JWKS service. Default value is 10 seconds.
- `jwks_service_time_to_live` (Number) The amount of time, in minutes, that the JWKS will be considered valid. Once the JWKS has expired, it will have to be retrieved again.
							Default value is 1 hour. Ignore this field if the JWT Signing Method was set to None.
- `jwks_url` (String) The Url to the JWKS server that contains the public keys for the signature validation.
							Ignore this field if the JWT Signing Method was set to None.
- `jwt_expression` (String) Mule Expression to be used to extract the JWT from API requests
- `mandatory_aud_claim` (Boolean) Whether to make Audience claim mandatory. If a claim is marked as mandatory, and this claim is not present in the incoming JWT, the request will fail.
- `mandatory_custom_claims` (Block List) Specify the Claim Name and the literal to validate the value of a claim E.g foo : fooValue If more complex validations must be made or the claim value is an array or an object, provide Claim Name and DataWeave expression to validate the value of a claim.
							E.g. foo : #[vars.claimSet.foo == 'fooValue'] If a claim is marked as mandatory and this claim is not present in the incoming jwt, the request will fail. (see [below for nested schema](#nestedblock--configuration_data--mandatory_custom_claims))
- `mandatory_exp_claim` (Boolean) Whether to make Expiration claim mandatory. If a claim is marked as mandatory, and this claim is not present in the incoming JWT, the request will fail.
- `mandatory_nbf_claim` (Boolean) Whether to make Not Before claim mandatory. If a claim is marked as mandatory, and this claim is not present in the incoming JWT, the request will fail.
- `non_mandatory_custom_claims` (Block List) Specify the Claim Name and the literal to validate the value of a claim E.g foo : fooValue If more complex validations must be made or the claim value is an array or an object, provide Claim Name and DataWeave expression to validate the value of a claim.
							E.g. foo : #[vars.claimSet.foo == 'fooValue'] If a claim is marked as non-mandatory and this claim is not present in the incoming jwt, the request will not fail. (see [below for nested schema](#nestedblock--configuration_data--non_mandatory_custom_claims))
- `signing_key_length` (Number) Specifies the length of the key to be in the signing method for HMAC, or the SHA algorithm used for RSA or ES.
							Ignore this field if the JWT Signing Method was set to None.
- `skip_client_id_validation` (Boolean) Skips client application's API contract validation.
- `supported_audiences` (String) Comma separated list of supported audience values.
- `text_key` (String) The shared secret in case the JWT Signing Method is set to HMAC.
							Include the public PEM key without -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- for RSA or ES signing.
							Ignore this field if the JWT Signing Method was set to None.
- `validate_aud_claim` (Boolean) The JWT will be valid only if the aud claim contains at least one audiences value defined here.
- `validate_custom_claim` (Boolean) The JWT will be valid only if all DataWeave expressions defined in custom claims are.

<a id="nestedblock--configuration_data--mandatory_custom_claims"></a>
### Nested Schema for `configuration_data.mandatory_custom_claims`

Required:

- `key` (String) The claim name
- `value` (String) The value to compare against in literal or dataweave expression


<a id="nestedblock--configuration_data--non_mandatory_custom_claims"></a>
### Nested Schema for `configuration_data.non_mandatory_custom_claims`

Required:

- `key` (String) The claim name
- `value` (String) The value to compare against in literal or dataweave expression



<a id="nestedblock--pointcut_data"></a>
### Nested Schema for `pointcut_data`

Required:

- `method_regex` (Set of String) The list of HTTP methods
- `uri_template_regex` (String) URI template regex

## Import

Import is supported using the following syntax:

```shell
# In order for the import to work, you should provide a ID composed of the following:
#  {ORG_ID}/{ENV_ID}/{API_ID}/{API_POLICY_ID}

terraform import \
  -var-file params.tfvars.json \    #variables file
  anypoint_apim_policy_jwt_validation.policy02 \                #resource name
  aa1f55d6-213d-4f60-845c-207286484cd1/7074fcdd-9b23-4ab3-97c8-5db5f4adf17d/19250669/4720771      #resource ID
```