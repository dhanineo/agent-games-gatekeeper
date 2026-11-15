"use strict";
/*
 * Agent Games — Proof Gatekeeper agent.
 * Protocol: https://agentgames.zkverify.io/build (authoritative).
 *  - Inbound: POST /agent, HMAC-SHA256 over RAW body in `x-agent-games-signature`.
 *  - Outbound: JSON response, signed the same way in the response header.
 *  - Fail closed: any uncertainty -> REJECT.
 * Secrets come from env only: AGENT_GAMES_HMAC_SECRET, KURIER_API_KEY (optional).
 */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = process.env.PORT || 8787;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const SIG_FORMAT = process.env.SIG_FORMAT || "hex"; // hex | base64 | prefixed
const DIR = __dirname;
const WASM = path.join(DIR, "circuits", "gatekeeper.wasm");
const ZKEY = path.join(DIR, "circuits", "gatekeeper_final.zkey");
const SEEN_FILE = path.join(DIR, "seen_proofs.json");
const LOG_FILE = path.join(DIR, "agent.log");
const BN254_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function log(obj) {
  const line = JSON.stringify({ t: new Date().toISOString(), ...obj });
  try { fs.appendFileSync(LOG_FILE, line + "\n"); } catch (_) {}
  console.log(line);
}

/* ---------------- HMAC helpers ---------------- */
function hmacHex(raw) {
  return crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
}
function signHeader(rawBodyString) {
  const hex = hmacHex(rawBodyString);
  if (SIG_FORMAT === "base64")
    return crypto.createHmac("sha256", SECRET).update(rawBodyString).digest("base64");
  if (SIG_FORMAT === "prefixed") return "sha256=" + hex;
  return hex;
}
function verifyInbound(rawBuffer, headerVal) {
  if (!SECRET || !headerVal) return false;
  const raw = rawBuffer.toString("utf8");
  const candidates = [
    hmacHex(raw),
    "sha256=" + hmacHex(raw),
    crypto.createHmac("sha256", SECRET).update(raw).digest("base64"),
  ];
  const got = String(headerVal).trim();
  return candidates.some((c) => {
    try {
      const a = Buffer.from(c), b = Buffer.from(got);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (_) { return false; }
  });
}

/* ---------------- field encodings (CALIBRATION section) ----------------
 * The platform re-derives the public signals from the task data and checks
 * them against the proof. These encodings are the current best hypothesis;
 * practice mode is the ground truth used to calibrate them. */
function encodeHashToField(hexHash) {
  // 256-bit hash -> single BN254 field element via mod reduction.
  const v = BigInt(hexHash);
  return (v % BN254_PRIME).toString();
}
function encodeAddress(addr) {
  return BigInt(addr).toString();
}
let keccak256 = null;
try { keccak256 = require("ethers").keccak256; } catch (_) {}
function encodeTaskId(taskId) {
  // Hypothesis A: keccak256(utf8(task_id)) mod p.
  if (keccak256) {
    const h = keccak256(Buffer.from(String(taskId), "utf8"));
    return (BigInt(h) % BN254_PRIME).toString();
  }
  return "0";
}

/* ---------------- seen proof_tx store (reuse trap) ---------------- */
let seenProofs = new Set();
try {
  seenProofs = new Set(JSON.parse(fs.readFileSync(SEEN_FILE, "utf8")));
} catch (_) {}
function markProofSeen(tx) {
  if (!tx) return;
  seenProofs.add(tx.toLowerCase());
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify([...seenProofs])); } catch (_) {}
}

/* ---------------- decision logic ---------------- */
const REASON = {
  OK: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  BALANCE: "THRESHOLD_MISMATCH",
  AMOUNT: "AMOUNT_MISMATCH",
  EXPIRED: "EXPIRED",
  REUSED: "PROOF_REUSED",
  NOT_FINAL: "PROOF_NOT_FINALIZED",
  MALFORMED: "MALFORMED_TASK",
  INTERNAL: "INTERNAL_ERROR",
};

function decide(input) {
  // Returns { decision: 1|0, reason_code } using deterministic checks only.
  try {
    if (!input || typeof input !== "object") return { decision: 0, reason_code: REASON.MALFORMED };
    const {
      registered_vk, proof_vk, minimum, public_balance, expiry_block,
      current_block, recipient, condition_recipient, amount, max_transfer, proof_tx,
    } = input;
    if (
      registered_vk == null || proof_vk == null || minimum == null ||
      public_balance == null || recipient == null || condition_recipient == null ||
      amount == null || max_transfer == null
    ) return { decision: 0, reason_code: REASON.MALFORMED };

    if (String(proof_vk).toLowerCase() !== String(registered_vk).toLowerCase())
      return { decision: 0, reason_code: REASON.VK };
    if (String(recipient).toLowerCase() !== String(condition_recipient).toLowerCase())
      return { decision: 0, reason_code: REASON.RECIPIENT };
    if (BigInt(public_balance) < BigInt(minimum))
      return { decision: 0, reason_code: REASON.BALANCE };
    if (BigInt(amount) > BigInt(max_transfer))
      return { decision: 0, reason_code: REASON.AMOUNT };
    if (expiry_block != null && current_block != null &&
        BigInt(current_block) > BigInt(expiry_block))
      return { decision: 0, reason_code: REASON.EXPIRED };
    if (proof_tx && seenProofs.has(String(proof_tx).toLowerCase()))
      return { decision: 0, reason_code: REASON.REUSED };
    return { decision: 1, reason_code: REASON.OK };
  } catch (_) {
    return { decision: 0, reason_code: REASON.MALFORMED };
  }
}

function circuitInputs(task, decision) {
  const i = task.input;
  return {
    decision: String(decision),
    minimum: String(i.minimum),
    publicBalance: String(i.public_balance),
    expiryBlock: String(i.expiry_block ?? "0"),
    currentBlock: String(i.current_block ?? "0"),
    recipient: encodeAddress(i.recipient),
    conditionRecipient: encodeAddress(i.condition_recipient),
    amount: String(i.amount),
    maxTransfer: String(i.max_transfer),
    taskId: encodeTaskId(task.task_id),
    registeredVkHash: encodeHashToField(i.registered_vk),
    proofVkHash: encodeHashToField(i.proof_vk),
    salt: String(i.salt ?? "0"),
  };
}

const responseCache = new Map(); // task_id -> response body string (idempotency)

async function handleGatekeeper(task) {
  const started = Date.now();
  let { decision, reason_code } = decide(task.input);
  let proof = null, publicSignals = null, proofErr = null, flipped = false;
  // The circuit itself computes the correct evaluation and asserts the
  // claimed decision matches it. If witness generation fails for our
  // decision, flip it: exactly one decision value is provable per input set.
  for (const attempt of [decision, 1 - decision]) {
    try {
      const r = await snarkjs.groth16.fullProve(circuitInputs(task, attempt), WASM, ZKEY);
      proof = r.proof; publicSignals = r.publicSignals;
      if (attempt !== decision) {
        flipped = true;
        decision = attempt;
        reason_code = decision === 1 ? REASON.OK : (reason_code === REASON.OK ? "EVALUATION_MISMATCH" : reason_code);
      }
      proofErr = null;
      break;
    } catch (e) {
      proofErr = String(e).slice(0, 200);
    }
  }
  if (task.input && task.input.proof_tx) markProofSeen(task.input.proof_tx);
  const body = {
    decision: decision === 1 ? "APPROVE" : "REJECT",
    reason_code,
    ...(proof ? { proof, public_signals: publicSignals } : {}),
    ...(task.input && task.input.proof_tx ? { proof_tx: task.input.proof_tx } : {}),
  };
  log({
    kind: "gatekeeper", task_id: task.task_id, mode: task.mode,
    decision: body.decision, reason_code, proof: !!proof, proofErr, flipped,
    ms: Date.now() - started,
  });
  return body;
}

/* ---------------- HTTP server ---------------- */
const server = http.createServer((req, res) => {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, service: "gatekeeper-agent", protocolVersion: "v1" }));
    return;
  }
  if (req.method !== "POST") { res.writeHead(405); res.end(); return; }
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const rawStr = raw.toString("utf8");
    const sigHeader = req.headers["x-agent-games-signature"];
    const send = (obj) => {
      const bodyStr = JSON.stringify(obj);
      res.writeHead(200, {
        "content-type": "application/json",
        "x-agent-games-signature": signHeader(bodyStr),
      });
      res.end(bodyStr);
    };
    if (!verifyInbound(raw, sigHeader)) {
      log({ kind: "auth_fail", sig_present: !!sigHeader, sig_len: sigHeader ? String(sigHeader).length : 0, body_len: raw.length });
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "bad signature" }));
      return;
    }
    let msg;
    try { msg = JSON.parse(rawStr); } catch (_) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "bad json" }));
      return;
    }
    try {
      if (msg.type === "agent-games.preflight.v1") {
        log({ kind: "preflight", agent_id: msg.agent_id });
        return send({ ok: true, protocolVersion: "v1" });
      }
      if (msg.type === "agent-games.proof-gatekeeper.v1") {
        if (msg.task_id && responseCache.has(msg.task_id)) {
          const bodyStr = responseCache.get(msg.task_id);
          res.writeHead(200, {
            "content-type": "application/json",
            "x-agent-games-signature": signHeader(bodyStr),
          });
          return res.end(bodyStr);
        }
        const body = await handleGatekeeper(msg);
        if (msg.task_id) responseCache.set(msg.task_id, JSON.stringify(body));
        return send(body);
      }
      log({ kind: "unknown_type", type: msg.type });
      return send({ ok: false, error: "unknown type" });
    } catch (e) {
      log({ kind: "handler_error", err: String(e).slice(0, 200) });
      return send({ decision: "REJECT", reason_code: REASON.INTERNAL });
    }
  });
});

server.listen(PORT, () => log({ kind: "listen", port: PORT, secret_set: !!SECRET }));
