#!/bin/sh
# Download the official Proof Gatekeeper circuit artifacts from Agent Games.
mkdir -p circuits
curl -sL -o circuits/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL -o circuits/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
echo "artifacts downloaded to circuits/"
