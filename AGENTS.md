## Ownership

- A owns `agent-aa/`: Python Agent and Authorization Authority.
- B owns `credential-broker/`: Go Credential Broker and Vault. A may update only shared contracts or the B skeleton/notes; do not implement B business logic here.
- C owns `evaluation-dashboard/`: security/performance evaluation and visualization. A may update only interface notes or sample definitions; do not claim C results from A tests.
- Cross-language contracts live in `shared/`. A and B must review changes to signed fields, canonicalization, signature input, SM2 user ID, key/signature encoding, or error semantics.

## Security invariants

- The AA authorizes only from its server-owned trusted task store. Agent-supplied context is data, not authority.
- The Agent never receives a target service's long-term Credential.
- Every protected request is bound to Agent, task, service, resource, operation, canonical request hash, audience, Credential ID/epoch, TTL, and nonce.
- Holder Proof binds the exact signed Capability, actual request, Broker audience, and a fresh Broker challenge.
- Fail closed on parse, schema, key, signature, time, lifecycle, replay, or binding errors.
- Do not hand-write SM2, SM3, or SM4 primitives and do not silently change algorithms.
- Never commit real private keys, Credentials, tokens, runtime state, or generated `.runtime/` data.
