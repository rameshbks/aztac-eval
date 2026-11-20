# AZTAC policy decision point in Rego (equivalent to aztac/pdp.py:decide).
# Query: POST /v1/data/aztac/decision  {"input": {details, tool, args, mode, meta}}
package aztac

import rego.v1

meta := input.meta

entries := [e | some e in input.details; e.type == "agent_tool_invocation"; input.tool in e.actions]

has_entry if count(entries) > 0

entry := entries[0] if has_entry

read_mode := m if {
	some e in input.details
	e.type == "agent_read_policy"
	m := e.mode
} else := "scoped"

unlisted_write := u if {
	some e in input.details
	e.type == "agent_read_policy"
	u := e.unlisted_write
} else := "deny"

url_args := {"url"}

strip_slash(s) := substring(s, 0, count(s) - 1) if endswith(s, "/")

strip_slash(s) := s if not endswith(s, "/")

canon(a, x) := strip_slash(regex.replace(lower(trim_space(x)), "^(https?://)?(www\\.)?", "")) if {
	is_string(x)
	a in url_args
}

canon(a, x) := lower(trim_space(x)) if {
	is_string(x)
	not a in url_args
}

canon(_, x) := json.marshal(x) if {
	not is_string(x)
	is_object(x)
}

canon(_, x) := json.marshal(x) if {
	not is_string(x)
	is_array(x)
}

canon(_, x) := x if {
	not is_string(x)
	not is_object(x)
	not is_array(x)
}

vals(a, v) := [canon(a, x) | some x in v] if is_array(v)

vals(_, v) := [] if v == null

vals(a, v) := [canon(a, v)] if {
	not is_array(v)
	v != null
}

arg(a) := object.get(input.args, a, null)

targets := sort([k | some k, _ in input.args]) if meta.targets == ["*"]

targets := meta.targets if meta.targets != ["*"]

constraints := object.get(entry, "constraints", {})

bounds := object.get(entry, "bounds", {})

present(a) if count(vals(a, arg(a))) > 0

unpinned contains a if {
	some a in targets
	present(a)
	not constraints[a]
}

bad_vals(a) := [v | some v in vals(a, arg(a)); not v in constraints[a]]

good_vals(a) := [v | some v in vals(a, arg(a)); v in constraints[a]]

violating contains a if {
	some a in targets
	present(a)
	constraints[a]
	count(bad_vals(a)) > 0
}

narrowable contains a if {
	some a in violating
	is_array(arg(a))
	count(good_vals(a)) > 0
}

pinned_bad contains a if {
	some a in violating
	not a in narrowable
}

over_bound contains a if {
	some a, b in bounds
	is_number(arg(a))
	arg(a) > b
}

violations := array.concat(
	array.concat(
		[sprintf("target_outside_scope:%s", [a]) | some a in violating],
		[sprintf("unpinned_target:%s", [a]) | some a in unpinned],
	),
	[sprintf("bound_exceeded:%s", [a]) | some a in over_bound],
)

reason := concat("; ", violations)

decision := d if {
	not has_entry
	meta.class == "read"
	read_mode == "suite"
	d := {"outcome": "ALLOW", "reason": "read tool permitted by suite read policy", "violations": []}
} else := d if {
	not has_entry
	meta.class != "read"
	unlisted_write == "step_up"
	input.mode == "graduated"
	d := {"outcome": "STEP_UP", "reason": sprintf("tool '%s' not in task scope; human approval required", [input.tool]), "violations": ["tool_unlisted"]}
} else := d if {
	not has_entry
	d := {"outcome": "DENY", "reason": sprintf("tool '%s' not in task scope", [input.tool]), "violations": ["tool_out_of_scope"]}
} else := d if {
	meta.class == "read"
	d := {"outcome": "ALLOW", "reason": "read tool in task scope", "violations": []}
} else := d if {
	count(violations) == 0
	d := {"outcome": "ALLOW", "reason": "call within task scope", "violations": []}
} else := d if {
	input.mode == "strict"
	d := {"outcome": "DENY", "reason": reason, "violations": violations}
} else := d if {
	count(pinned_bad) > 0
	d := {"outcome": "DENY", "reason": reason, "violations": violations}
} else := d if {
	count(unpinned) + count(over_bound) > 0
	d := {"outcome": "STEP_UP", "reason": reason, "violations": violations}
} else := d if {
	narrowed := {a: [x | some x in input.args[a]; canon(a, x) in constraints[a]] | some a in narrowable}
	d := {"outcome": "NARROW", "reason": reason, "violations": violations, "args": object.union(input.args, narrowed)}
}
