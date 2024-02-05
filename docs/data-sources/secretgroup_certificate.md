---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "anypoint_secretgroup_certificate Data Source - terraform-provider-anypoint"
subcategory: ""
description: |-
  Query a specific certificate for a secret-group in a given organization and environment.
---

# anypoint_secretgroup_certificate (Data Source)

Query a specific certificate for a secret-group in a given organization and environment.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `env_id` (String) The environment id where the certificate's secret group is defined.
- `id` (String) Id assigned to this certificate
- `org_id` (String) The organization id where the certificate's secret group is defined.
- `sg_id` (String) The secret-group id where the certificate instance is defined.

### Read-Only

- `certificate_file_name` (String) The file name of the certificate
- `details` (List of Object) Details of the certificate (see [below for nested schema](#nestedatt--details))
- `expiration_date` (String) The expiration date of the certificate
- `name` (String) The name of the certificate
- `path` (String) The path of the keystore
- `type` (String) The specific type of the certificate

<a id="nestedatt--details"></a>
### Nested Schema for `details`

Read-Only:

- `certificate_type` (String)
- `extended_key_usage` (List of String)
- `is_certificate_authority` (Boolean)
- `issuer` (Map of String)
- `key_usage` (List of String)
- `public_key_algorithm` (String)
- `serial_number` (String)
- `signature_algorithm` (String)
- `subject` (Map of String)
- `subject_alternative_name` (List of String)
- `validity` (Map of String)
- `version` (String)

