---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "anypoint_secretgroup_tlscontext_securityfabric Data Source - terraform-provider-anypoint"
subcategory: ""
description: |-
  Query a specific tls-context of type security-fabric for a secret-group in a given organization and environment.
---

# anypoint_secretgroup_tlscontext_securityfabric (Data Source)

Query a specific tls-context of type security-fabric for a secret-group in a given organization and environment.



<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `env_id` (String) The environment id where the tls-context's secret group is defined.
- `id` (String) Id assigned to this tls-context
- `org_id` (String) The organization id where the tls-context's secret group is defined.
- `sg_id` (String) The secret-group id where the tls-context instance is defined.

### Read-Only

- `acceptable_cipher_suites` (List of Object) List of accepted cipher suites by Security Fabric target, at least one should be set to true. If you are are not using the defaults and select individual ciphers, please select ciphers that match the configured keystore to ensure that TLS can setup a connection.
        For a keystore with an RSA key (the most common type), select ciphers which contain the string RSA (there are some exceptions). If using ECC ciphers, select ciphers which contain the string "ECDSA".
        TLS standards and documentation can be consulted for more background information. (see [below for nested schema](#nestedatt--acceptable_cipher_suites))
- `acceptable_tls_versions` (List of Object) TLS versions supported. (see [below for nested schema](#nestedatt--acceptable_tls_versions))
- `enable_mutual_authentication` (Boolean) This flag is to enable client authentication.
- `expiration_date` (String) The expiration date of the tls-context
- `keystore_path` (String) Refers to a secret of type keystore. Relative path of the secret to be referenced.
- `mutual_authentication` (List of Object) Configuration for client authentication. (see [below for nested schema](#nestedatt--mutual_authentication))
- `name` (String) The name of the tls-context
- `path` (String) The path of the tls-context
- `target` (String) The target application for the tls-context
- `truststore_path` (String) Refers to a secret of type truststore. Relative path of the secret to be referenced.

<a id="nestedatt--acceptable_cipher_suites"></a>
### Nested Schema for `acceptable_cipher_suites`

Read-Only:

- `aes128_gcm_sha256` (Boolean)
- `aes128_sha256` (Boolean)
- `aes256_gcm_sha384` (Boolean)
- `aes256_sha256` (Boolean)
- `dhe_rsa_aes128_gcm_sha256` (Boolean)
- `dhe_rsa_aes128_sha256` (Boolean)
- `dhe_rsa_aes256_gcm_sha384` (Boolean)
- `dhe_rsa_aes256_sha256` (Boolean)
- `dhe_rsa_chacha20_poly1305` (Boolean)
- `ecdhe_ecdsa_aes128_gcm_sha256` (Boolean)
- `ecdhe_ecdsa_aes128_sha1` (Boolean)
- `ecdhe_ecdsa_aes256_gcm_sha384` (Boolean)
- `ecdhe_ecdsa_aes256_sha1` (Boolean)
- `ecdhe_ecdsa_chacha20_poly1305` (Boolean)
- `ecdhe_rsa_aes128_gcm_sha256` (Boolean)
- `ecdhe_rsa_aes128_sha1` (Boolean)
- `ecdhe_rsa_aes256_gcm_sha384` (Boolean)
- `ecdhe_rsa_aes256_sha1` (Boolean)
- `ecdhe_rsa_chacha20_poly1305` (Boolean)
- `tls_aes128_gcm_sha256` (Boolean)
- `tls_aes256_gcm_sha384` (Boolean)
- `tls_chacha20_poly1305_sha256` (Boolean)


<a id="nestedatt--acceptable_tls_versions"></a>
### Nested Schema for `acceptable_tls_versions`

Read-Only:

- `tls_v1_dot1` (Boolean)
- `tls_v1_dot2` (Boolean)
- `tls_v1_dot3` (Boolean)


<a id="nestedatt--mutual_authentication"></a>
### Nested Schema for `mutual_authentication`

Read-Only:

- `authentication_overrides` (List of Object) (see [below for nested schema](#nestedobjatt--mutual_authentication--authentication_overrides))
- `cert_checking_strength` (String)
- `certificate_pinning` (Map of String)
- `certificate_policies` (List of String)
- `certificate_policy_checking` (Boolean)
- `crl_distributor_config_path` (String)
- `perform_domain_checking` (Boolean)
- `require_crl_for_all_ca` (Boolean)
- `require_initial_explicit_policy` (Boolean)
- `revocation_checking` (Boolean)
- `revocation_checking_method` (String)
- `send_truststore` (Boolean)
- `verification_depth` (Number)

<a id="nestedobjatt--mutual_authentication--authentication_overrides"></a>
### Nested Schema for `mutual_authentication.authentication_overrides`

Read-Only:

- `allow_self_signed` (Boolean)
- `certificate_bad_format` (Boolean)
- `certificate_bad_signature` (Boolean)
- `certificate_has_expired` (Boolean)
- `certificate_not_yet_valid` (Boolean)
- `certificate_unresolved` (Boolean)
- `certificate_untrusted` (Boolean)
- `invalid_ca` (Boolean)
- `invalid_purpose` (Boolean)
- `other` (Boolean)

