package agent_guard.v2
import rego.v1

default allow := false

covers(scope, prefix_flag, resource) if { resource == scope }
covers(scope, prefix_flag, resource) if {
    prefix_flag
    startswith(resource, concat("", [scope, "/"]))
}

scope_narrows(parent, child) if { parent.prefix }
scope_narrows(parent, child) if { not child.prefix }

attenuates(parent, child) if {
    child.parent == parent.id
    child.issuer == parent.subject
    child.operation == parent.operation
    covers(parent.resource, parent.prefix, child.resource)
    scope_narrows(parent, child)
    child.expires <= parent.expires
    child.remaining < parent.remaining
}

edge_ok(i, chain) if { i == 0 }
edge_ok(i, chain) if { i > 0; attenuates(chain[i-1], chain[i]) }

valid_chain(chain) if {
    count(chain) > 0
    chain[0] in input.roots
    every g in chain {
        not g.id in input.revoked
        input.now < g.expires
    }
    every i, _ in chain { edge_ok(i, chain) }
}

delegation_edge(leaf) if { input.effect != "delegate" }
delegation_edge(leaf) if { input.effect == "delegate"; input.child != null; attenuates(leaf, input.child) }

permitted_chain(chain) if {
    valid_chain(chain)
    leaf := chain[count(chain)-1]
    leaf.subject == input.actor
    leaf.operation == input.operation
    covers(leaf.resource, leaf.prefix, input.resource)
    delegation_edge(leaf)
}

grant_authority if { some chain in input.chains; permitted_chain(chain) }

delegation_ok if { input.effect != "delegate" }
delegation_ok if {
    input.child != null
    input.child.issuer == input.actor
    input.child.subject in input.principals
    not input.child.id in input.grantIds
    input.now < input.child.expires
}

revoker if { input.actor in input.administrators }
revoker if { input.actor == input.target.issuer }
revoker if { input.actor == input.target.subject }

authority if { input.effect != "revoke"; grant_authority; delegation_ok }
authority if {
    input.effect == "revoke"
    input.target != null
    not input.target.id in input.revoked
    revoker
}

denied if {
    some d in input.denies
    d.actor == input.actor
    d.operation in {input.operation, input.actionOp}
    covers(d.resource, d.prefix, input.resource)
}

budget_ok if { input.budget == null }
budget_ok if { input.budget != null; input.count < input.budget }
flow_ok if { input.effect != "send" }
flow_ok if { input.effect == "send"; every label in input.labels { label in input.accepts } }

allow if {
    input.supported
    input.actor == input.identity
    input.actor in input.principals
    budget_ok
    not denied
    authority
    flow_ok
}

next_labels := sort({x | x := input.labels[_]} | {x | x := input.objectLabels[_]}) if {
    allow
    input.effect == "read"
} else := sort(input.labels)

decision := {"allow": allow, "nextLabels": next_labels}
