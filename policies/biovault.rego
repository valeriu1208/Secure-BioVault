package biovault.authz

import future.keywords.if
import future.keywords.in

# Security by Default => refuse all
default allow := false

# RULE 1: Admin has full access
allow if {
    input.subject.role == "ADMIN"
}

# RULE 2: Owner (patient) can access its own files
allow if {
    input.subject.id == input.resource.owner_id
}

# RULE 3: Explicit consent to a particular user
allow if {
    input.subject.role in ["DOCTOR", "RESEARCHER"]
    input.action in ["list", "read"]
    input.subject.id in input.resource.allowed_users
}

# RULE 4: Global permission given to a a un role
allow if {
    input.subject.role in ["DOCTOR", "RESEARCHER"]
    input.action in ["list", "read"]
    input.subject.role in input.resource.allowed_roles
}
