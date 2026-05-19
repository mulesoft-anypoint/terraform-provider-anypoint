# Importing an existing anypoint_private_space_vpn requires a composite id
# of the form:
#
#   {ORG_ID}/{PRIVATE_SPACE_ID}/{CONNECTION_ID}
#
# All three components are GUIDs. CONNECTION_ID is the `id` returned by the
# Anypoint Private Space "Connections" API; it is also the value shown in
# the URL of the Anypoint UI when editing a VPN connection.

terraform import \
  -var-file params.tfvars.json \
  anypoint_private_space_vpn.my_vpn \
  aa1f55d6-213d-4f60-845c-201282484cd1/7f747999-a9bb-41d5-bfe8-d6b8cca68c62/4d2c0e91-2c11-4f5e-91a0-3a7c3b1f7a90

# After import, run `terraform plan` to verify that no drift is detected.
# The first plan after import will typically show a `psk = (sensitive value)`
# drift on every tunnel because the API never returns PSKs — set the matching
# PSK values in your configuration to clear the diff. See the resource
# documentation for the full list of write-only fields.
