package biovault.authz

import rego.v1

test_owner_can_read_file if {
	allow with input as {
		"subject": {"id": "patient-1", "role": "PATIENT"},
		"action": "read",
		"resource": {"type": "file", "owner_id": "patient-1"},
	}
}

test_non_owner_cannot_read_file if {
	not allow with input as {
		"subject": {"id": "doctor-1", "role": "DOCTOR"},
		"action": "read",
		"resource": {"type": "file", "owner_id": "patient-1"},
	}
}

test_owner_cannot_use_unknown_action if {
	not allow with input as {
		"subject": {"id": "patient-1", "role": "PATIENT"},
		"action": "export",
		"resource": {"type": "file", "owner_id": "patient-1"},
	}
}
