---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "anypoint_secretgroup_certificates Data Source - terraform-provider-anypoint"
subcategory: ""
description: |-
  Query all or part of available certificates for a given secret-group, organization and environment.
---

# anypoint_secretgroup_certificates (Data Source)

Query all or part of available certificates for a given secret-group, organization and environment.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `env_id` (String) The environment id where the keystore instance is defined.
- `org_id` (String) The organization id where the keystore instance is defined.
- `sg_id` (String) The secret-group id where the keystore instance is defined.

### Read-Only

- `certificates` (List of Object) List certificates result of the query (see [below for nested schema](#nestedatt--certificates))
- `id` (String) The ID of this resource.

<a id="nestedatt--certificates"></a>
### Nested Schema for `certificates`

Read-Only:

- `expiration_date` (String)
- `id` (String)
- `name` (String)
- `path` (String)
- `type` (String)

