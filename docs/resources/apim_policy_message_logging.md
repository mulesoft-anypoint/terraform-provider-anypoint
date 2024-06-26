---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "anypoint_apim_policy_message_logging Resource - terraform-provider-anypoint"
subcategory: ""
description: |-
  Create and manage an API Policy of type message-logging.
---

# anypoint_apim_policy_message_logging (Resource)

Create and manage an API Policy of type message-logging.

## Example Usage

```terraform
resource "anypoint_apim_policy_message_logging" "policy01" {
  org_id = var.root_org
  env_id = var.env_id
  apim_id = anypoint_apim_mule4.api.id
  disabled = false
  asset_version = "2.0.1"
  configuration_data {
    logging_configuration {
      name = "configuration 01"
      message = "#[attributes.headers['id']]"
      conditional = "#[attributes.headers['id']==1]"
      category = "My_01_Prefix_"
      level = "INFO"
      first_section = true
      second_section = false
    }
    logging_configuration {
      name = "configuration 02"
      message = "#[attributes.headers['Authorization']]"
      level = "DEBUG"
      first_section = true
      second_section = false
    }
  }
}

resource "anypoint_apim_policy_message_logging" "policy02" {
  org_id = var.root_org
  env_id = var.env_id
  apim_id = anypoint_apim_mule4.api02.id
  disabled = false
  asset_version = "2.0.1"
  configuration_data {
    logging_configuration {
      name = "configuration 01"
      message = "#[attributes.headers['id']]"
      conditional = "#[attributes.headers['id']==1]"
      category = "My_01_Prefix_"
      level = "INFO"
      first_section = true
      second_section = false
    }
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

- `logging_configuration` (Block List, Min: 1) The list of logging configurations (see [below for nested schema](#nestedblock--configuration_data--logging_configuration))

<a id="nestedblock--configuration_data--logging_configuration"></a>
### Nested Schema for `configuration_data.logging_configuration`

Required:

- `message` (String) DataWeave Expression for extracting information from the message to log. e.g. #[attributes.headers['id']]
- `name` (String) The configuration name

Optional:

- `category` (String) Prefix in the log sentence.
- `conditional` (String) DataWeave Expression to filter which messages to log. e.g. #[attributes.headers['id']==1]
- `first_section` (Boolean) Log before calling the API
- `level` (String) Logging level, possible values: INFO, WARN, ERROR or DEBUG
- `second_section` (Boolean) Logging after calling the API



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
  anypoint_apim_policy_message_logging.policy01 \                #resource name
  aa1f55d6-213d-4f60-845c-207286484cd1/7074fcdd-9b23-4ab3-97c8-5db5f4adf17d/19250669/4720771      #resource ID
```
