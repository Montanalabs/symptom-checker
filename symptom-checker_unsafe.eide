#! VULNERABLE symptom-checker — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant advise confidence 70

let raw = fetch<web>
privileged { advise(raw) }  # tainted -> tool: REJECTED
