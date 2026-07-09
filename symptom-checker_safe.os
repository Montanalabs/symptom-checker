#! Symptom checker — untrusted a symptom report can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires advise — the symptom checker sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant advise confidence 70

type Level = SelfCare | SeeDoctor | Emergency
type Decision = Advise(Level) | Escalate

let raw = fetch<web>  # UNTRUSTED a symptom report — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { advise(d) }  # act on the trusted decision only
