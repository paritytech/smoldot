import { start } from "smoldot";
import {
  createSignedStatement,
  decodeStatement,
  getPublicKey,
  toHex,
} from "./statement.js";

const LOG = {
  ERROR: 1,
  WARN: 2,
  INFO: 3,
  DEBUG: 4,
  TRACE: 5,
};

const LOG_LABEL = {
  1: "ERROR",
  2: "WARN",
  3: "INFO",
  4: "DEBUG",
  5: "TRACE",
};

const BASE_LOG_LEVEL = LOG.INFO;
const TARGET = "app";

const statusEl = document.getElementById("status");
const topicInput = document.getElementById("topicInput");
const subscribeBtn = document.getElementById("subscribeBtn");
const messagesEl = document.getElementById("messages");
const messageInput = document.getElementById("messageInput");
const sendBtn = document.getElementById("sendBtn");
const logEl = document.getElementById("log");

let chain = null;
let currentTopic = null;
let requestId = 1;
let subscriptionId = null;
let myPublicKey = null;
const pendingRequests = new Map();

function log(level, target, message) {
  if (level > BASE_LOG_LEVEL) return;

  const label = LOG_LABEL[level] || "UNKNOWN";
  const entry = document.createElement("small");
  entry.style.display = "block";
  entry.textContent = `${label} [${target}] ${message}`;
  logEl.appendChild(entry);
  logEl.scrollTop = logEl.scrollHeight;
  console.log(`${label} [${target}] ${message}`);
}

function addMessage(content, type) {
  const placeholder = document.getElementById("no-messages");
  if (placeholder) placeholder.remove();

  const msg = document.createElement("div");
  msg.className = "section";
  const time = new Date().toLocaleTimeString();
  const label = type === "sent" ? "You" : "Received";

  const small = document.createElement("small");
  small.style.display = "block";
  small.textContent = `${label} - ${time}`;

  msg.appendChild(small);
  msg.appendChild(document.createTextNode(content));

  messagesEl.appendChild(msg);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function initialize() {
  try {
    log(LOG.INFO, TARGET, "Starting smoldot for statement store...");
    statusEl.textContent = "Starting smoldot...";

    const smoldot = start({
      maxLogLevel: BASE_LOG_LEVEL,
      logCallback: log,
    });

    log(LOG.DEBUG, TARGET, "Loading chain specs...");
    const relayChainSpec = await loadChainSpec("/chain-specs/relay.json");
    const parachainSpec = await loadChainSpec("/chain-specs/parachain.json");

    log(LOG.DEBUG, TARGET, "Adding relay chain...");
    const relayChain = await smoldot.addChain({ chainSpec: relayChainSpec });

    log(LOG.DEBUG, TARGET, "Adding parachain...");
    chain = await smoldot.addChain({
      chainSpec: parachainSpec,
      potentialRelayChains: [relayChain],
      statementStore: {},
    });

    log(LOG.DEBUG, TARGET, "Setting up JSON-RPC handler...");
    setupJsonRpcHandler(chain);

    statusEl.textContent = "Connected to parachain";

    myPublicKey = await getPublicKey();
    log(LOG.INFO, TARGET, `Statement signing key: ${myPublicKey}`);

    subscribeBtn.disabled = false;
    topicInput.value =
      "0x0000000000000000000000000000000000000000000000000000000000000001";
  } catch (error) {
    log(LOG.ERROR, TARGET, `Failed to initialize: ${error.message}`);
    statusEl.textContent = `Error: ${error.message}`;
    console.error(error);
  }
}

async function loadChainSpec(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(
      `Failed to load chain spec from ${path}: ${response.statusText}`,
    );
  }
  return await response.text();
}

async function subscribeToTopic() {
  const topic = topicInput.value.trim();

  if (!topicInput.checkValidity()) {
    log(LOG.WARN, TARGET, "Invalid topic format. Must be 0x followed by 64 hex characters.");
    return;
  }

  try {
    if (subscriptionId) {
      try {
        await sendJsonRpc("statement_unsubscribe", [subscriptionId]);
      } catch (e) {
        log(LOG.WARN, TARGET, `Failed to unsubscribe from previous topic: ${e.message}`);
      }
    }

    log(LOG.DEBUG, TARGET, `Subscribing to topic: ${topic}`);
    subscriptionId = await sendJsonRpc("statement_subscribe", [
      { type: "match_any", topics: [topic] },
    ]);
    log(LOG.DEBUG, TARGET, `Subscription ID: ${subscriptionId}`);

    currentTopic = topic;
    log(LOG.INFO, TARGET, "Subscribed successfully!");
    statusEl.textContent = `Subscribed to: ${topic}`;

    messageInput.disabled = false;
    sendBtn.disabled = false;
    subscribeBtn.textContent = "Change";
  } catch (error) {
    log(LOG.ERROR, TARGET, `Failed to subscribe: ${error.message}`);
    console.error(error);
  }
}

async function sendStatement() {
  const message = messageInput.value.trim();
  if (!message || !currentTopic) return;

  try {
    const statementHex = await createSignedStatement(currentTopic, message);
    log(LOG.DEBUG, TARGET, `Sending signed statement: ${message}`);

    const result = await sendJsonRpc("statement_submit", [statementHex]);

    if (result?.ok_broadcast) {
      messageInput.value = "";
      addMessage(message, "sent");
      log(
        LOG.INFO,
        TARGET,
        `Statement broadcast to ${result.ok_broadcast.sent}/${result.ok_broadcast.total} peers`,
      );
    } else if (result?.error) {
      log(LOG.ERROR, TARGET, `Failed to send: ${result.error}`);
    } else {
      messageInput.value = "";
      log(LOG.DEBUG, TARGET, `Statement submit result: ${JSON.stringify(result)}`);
    }
  } catch (error) {
    log(LOG.ERROR, TARGET, `Failed to send statement: ${error.message}`);
    console.error(error);
  }
}

function handleStatementNotification(statementHex) {
  try {
    const decoded = decodeStatement(statementHex);
    if (decoded.data) {
      const signerHex = decoded.proof?.signer
        ? toHex(decoded.proof.signer)
        : null;
      const isOurs = signerHex === myPublicKey;
      addMessage(decoded.data, isOurs ? "sent" : "received");
    }
  } catch (e) {
    log(LOG.ERROR, TARGET, `Failed to decode statement: ${e.message}`);
  }
}

async function sendJsonRpc(method, params) {
  const id = requestId++;
  const request = JSON.stringify({
    jsonrpc: "2.0",
    id: id.toString(),
    method,
    params,
  });

  const promise = new Promise((resolve, reject) => {
    pendingRequests.set(id.toString(), { resolve, reject });
  });

  chain.sendJsonRpc(request);
  return promise;
}

function setupJsonRpcHandler(chainInstance) {
  chain = chainInstance;

  (async () => {
    while (true) {
      const response = await chain.nextJsonRpcResponse();
      try {
        const parsed = JSON.parse(response);

        if (parsed.method === "statement_notification" && parsed.params) {
          handleStatementNotification(parsed.params.statement);
        } else if (parsed.id) {
          const pending = pendingRequests.get(parsed.id);
          if (pending) {
            pendingRequests.delete(parsed.id);
            if (parsed.error) {
              pending.reject(
                new Error(`JSON-RPC error: ${parsed.error.message}`),
              );
            } else {
              pending.resolve(parsed.result);
            }
          } else {
            log(LOG.WARN, TARGET, `Unexpected response for unknown request ID: ${parsed.id}`);
          }
        }
      } catch (e) {
        log(LOG.ERROR, TARGET, `Failed to handle JSON-RPC response: ${e.message}`);
        console.error("JSON-RPC handler error:", e);
      }
    }
  })();
}

subscribeBtn.addEventListener("click", subscribeToTopic);
sendBtn.addEventListener("click", sendStatement);
messageInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !sendBtn.disabled) {
    sendStatement();
  }
});
topicInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter" && !subscribeBtn.disabled) {
    subscribeToTopic();
  }
});

initialize();
