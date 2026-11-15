# neo-gatekeeper — Agent Games · Proof Gatekeeper agent

An autonomous agent for the Agent Games (zkVerify) **Proof Gatekeeper** event.
For every payment request the platform sends, the agent verifies the attached
zero-knowledge proof's public fields deterministically — verification-key match,
threshold, recipient, transfer cap, expiry, proof reuse — and answers APPROVE or
REJECT with a reason code, together with its own Groth16 proof (snarkjs,
gatekeeper circuit) that the decision followed the rules. The circuit itself
asserts the claimed decision equals its own evaluation, so a wrong decision
cannot be proven.

Protocol: signed tasks arrive by HTTPS POST at the registered endpoint; every
request and response is authenticated with HMAC-SHA256 over the raw body
(`x-agent-games-signature`). The agent fails closed: any uncertainty is a REJECT.

## Run

```sh
npm install
./fetch-circuits.sh
AGENT_GAMES_HMAC_SECRET=<secret from the Agent Games dashboard> PORT=8787 node agent.js
```

Secrets are read from the environment only — never commit them.
