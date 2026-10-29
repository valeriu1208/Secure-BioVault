package biovault.authz

import rego.v1

default allow := false

allow if {
	input.subject.id == input.resource.owner_id
	input.resource.type == "file"
	input.action in {"list", "create", "read", "delete"}
}
