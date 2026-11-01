package biovault.authz

import future.keywords.if
import future.keywords.in

# Security by Default => refuse all
default allow := false

# RULE 1: Admin has full access
allow if {
    input.subject.role == "ADMIN"
}

# RULE 2: Owner (patient) can access its own files with valid actions
allow if {
    input.subject.id == input.resource.owner_id
    input.action in ["list", "read", "write", "delete"]
}

# RULE 3: Doctors with user-specific or role-base consent
allow if {
    input.subject.role == "DOCTOR"
    input.action in ["list", "read"]
    is_access_allowed
}

# RULE 4: Researchers with user-specific or role-based consent
allow if {
    input.subject.role == "RESEARCHER"
    input.action in ["list", "read"]
    is_access_allowed
}

# --- HELPERS ---

# Check if access is explicitly allowed by user ID or role
is_access_allowed if {
    input.subject.id in input.resource.allowed_users
}

is_access_allowed if {
    input.subject.role in input.resource.allowed_roles
}