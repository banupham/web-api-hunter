const SERVER = "http://127.0.0.1:8765/event";

let attachedTabs = new Set();
const requests = new Map();          // request_key -> record
const requestGeneration = new Map(); // tabId:requestId -> generation
const websockets = new Map();        // tabId:requestId -> url
let actionByTab = {};                // tabId -> {active,name}

const SENSITIVE_HEADER_RE = /(authorization|cookie|csrf|xsrf|token|secret|api[-_]?key|ticket[-_]?guard|secsdk|signature)/i;
const SENSITIVE_QUERY_RE = /^(msToken|X-Bogus|X-Gnarly|X-Dynosaur|signature|sign|token|access_token|auth|authorization|device_id|ttwid)$/i;
const SENSITIVE_BODY_KEY_RE = /(authorization|cookie|csrf|xsrf|token|secret|api[-_]?key|ticket[-_]?guard|secsdk|signature)/i;

function redactHeaders(h) {
  const out = {};
  for (const [k,v] of Object.entries(h || {})) {
    out[k] = SENSITIVE_HEADER_RE.test(String(k)) ? "[REDACTED]" : v;
  }
  return out;
}

function redactUrl(raw) {
  try {
    const u = new URL(raw);
    for (const key of [...u.searchParams.keys()]) {
      if (SENSITIVE_QUERY_RE.test(key) || SENSITIVE_HEADER_RE.test(key)) {
        u.searchParams.set(key, "[REDACTED]");
      }
    }
    return u.toString();
  } catch (_) {
    return raw;
  }
}

function redactObject(value, depth=0) {
  if (depth > 8) return value;
  if (Array.isArray(value)) return value.map(v => redactObject(v, depth+1));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k,v] of Object.entries(value)) {
      out[k] = SENSITIVE_BODY_KEY_RE.test(k) ? "[REDACTED]" : redactObject(v, depth+1);
    }
    return out;
  }
  return value;
}

function redactPostData(raw) {
  if (typeof raw !== "string" || !raw) return raw || null;

  // JSON body.
  const t = raw.trim();
  if (t.startsWith("{") || t.startsWith("[")) {
    try {
      return JSON.stringify(redactObject(JSON.parse(raw)));
    } catch (_) {}
  }

  // URL encoded / form body.
  if (raw.includes("=")) {
    try {
      const p = new URLSearchParams(raw);
      let changed = false;
      for (const key of [...p.keys()]) {
        if (SENSITIVE_BODY_KEY_RE.test(key)) {
          p.set(key, "[REDACTED]");
          changed = true;
        }
      }
      if (changed) return p.toString();
    } catch (_) {}
  }

  return raw;
}

function socketKey(tabId, requestId) {
  return `${tabId}:${requestId}`;
}

function requestBaseKey(tabId, requestId) {
  return `${tabId}:${requestId}`;
}

function nextRequestKey(tabId, requestId, hasRedirect) {
  const base = requestBaseKey(tabId, requestId);
  let gen = requestGeneration.get(base) || 0;
  if (hasRedirect) gen += 1;
  requestGeneration.set(base, gen);
  return `${base}:${gen}`;
}

function currentRequestKey(tabId, requestId) {
  const base = requestBaseKey(tabId, requestId);
  const gen = requestGeneration.get(base) || 0;
  return `${base}:${gen}`;
}

function getAction(tabId) {
  const s = actionByTab[String(tabId)] || {};
  return {action_window: !!s.active, action_name: s.active ? (s.name || "Action") : null};
}

async function persistState() {
  try {
    await chrome.storage.session.set({
      attachedTabs:[...attachedTabs],
      actionByTab
    });
  } catch (_) {}
}

async function restoreState() {
  try {
    const st = await chrome.storage.session.get(["attachedTabs","actionByTab"]);
    attachedTabs = new Set(Array.isArray(st.attachedTabs) ? st.attachedTabs : []);
    actionByTab = st.actionByTab || {};
  } catch (_) {}
}
restoreState();

async function actualAttached(tabId) {
  try {
    const targets = await chrome.debugger.getTargets();
    return targets.some(t => t.tabId === tabId && t.attached);
  } catch (_) {
    return attachedTabs.has(tabId);
  }
}

async function sendEvent(obj) {
  obj.ts = obj.ts || Date.now()/1000;
  if (obj.tab_id != null && obj.kind !== "marker") {
    Object.assign(obj, getAction(obj.tab_id));
  }

  try {
    await fetch(SERVER, {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(obj)
    });
  } catch (e) {
    console.warn("Web API Hunter receiver unavailable", e);
  }
}

async function attachTab(tabId) {
  const isActual = await actualAttached(tabId);
  if (isActual) {
    attachedTabs.add(tabId);
    await persistState();
    return {ok:true, already:true};
  }

  await chrome.debugger.attach({tabId}, "1.3");
  await chrome.debugger.sendCommand({tabId}, "Network.enable", {
    maxTotalBufferSize:100000000,
    maxResourceBufferSize:25000000,
    maxPostDataSize:2000000
  });

  attachedTabs.add(tabId);
  await persistState();
  await sendEvent({kind:"marker", marker:"info", note:`attached tab ${tabId}`, tab_id:tabId});
  return {ok:true};
}

async function detachTab(tabId) {
  if (await actualAttached(tabId)) {
    try { await chrome.debugger.detach({tabId}); } catch (_) {}
  }

  attachedTabs.delete(tabId);
  delete actionByTab[String(tabId)];
  await persistState();

  await sendEvent({
    kind:"marker", marker:"info", note:`detached tab ${tabId}`, tab_id:tabId
  });

  return {ok:true};
}

chrome.debugger.onDetach.addListener(async (source) => {
  if (source.tabId != null) {
    attachedTabs.delete(source.tabId);
    delete actionByTab[String(source.tabId)];
    await persistState();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  attachedTabs.delete(tabId);
  delete actionByTab[String(tabId)];
  await persistState();
});

chrome.debugger.onEvent.addListener(async (source, method, params) => {
  const tabId = source.tabId;
  if (tabId == null) return;

  // After a MV3 service-worker restart, recover attachment state from actual debugger targets.
  if (!attachedTabs.has(tabId)) {
    if (!(await actualAttached(tabId))) return;
    attachedTabs.add(tabId);
    await persistState();
  }

  try {
    if (method === "Network.requestWillBeSent") {
      const req = params.request || {};
      const hasRedirect = !!params.redirectResponse;

      if (hasRedirect) {
        const oldKey = currentRequestKey(tabId, params.requestId);
        const old = requests.get(oldKey);
        const rr = params.redirectResponse || {};
        if (old) {
          Object.assign(old, {
            status:rr.status,
            mime_type:rr.mimeType,
            response_headers:redactHeaders(rr.headers)
          });
          await sendEvent({kind:"redirect_response", ...old});
        }
      }

      const requestKey = nextRequestKey(tabId, params.requestId, hasRedirect);

      const rec = {
        tab_id:tabId,
        request_id:params.requestId,
        request_key:requestKey,
        method:req.method,
        url:redactUrl(req.url),
        resource_type:params.type,
        request_headers:redactHeaders(req.headers),
        post_data:redactPostData(req.postData || null),
        initiator:params.initiator || null
      };

      requests.set(requestKey, rec);
      await sendEvent({kind:"request", ...rec});
    }

    else if (method === "Network.responseReceived") {
      const requestKey = currentRequestKey(tabId, params.requestId);
      const base = requests.get(requestKey) || {
        tab_id:tabId,
        request_id:params.requestId,
        request_key:requestKey
      };

      const res = params.response || {};
      Object.assign(base, {
        url:redactUrl(res.url || base.url),
        resource_type:params.type || base.resource_type,
        status:res.status,
        mime_type:res.mimeType,
        response_headers:redactHeaders(res.headers)
      });

      requests.set(requestKey, base);
      await sendEvent({kind:"response", ...base});
    }

    else if (method === "Network.loadingFinished") {
      const requestKey = currentRequestKey(tabId, params.requestId);
      const base = requests.get(requestKey);
      if (!base) return;

      const type = String(base.resource_type || "").toLowerCase();
      const mime = String(base.mime_type || "").toLowerCase();
      const url = String(base.url || "").toLowerCase();

      const interesting =
        ["xhr","fetch","document","eventsource","script"].includes(type) ||
        mime.includes("json") ||
        mime.includes("javascript") ||
        mime.includes("ecmascript") ||
        mime.includes("text/") ||
        mime.includes("protobuf") ||
        mime.includes("octet-stream") ||
        url.includes("graphql") ||
        url.includes("batchexecute") ||
        url.includes("/webcast/im/fetch");

      if (interesting) {
        try {
          const body = await chrome.debugger.sendCommand(
            {tabId}, "Network.getResponseBody", {requestId:params.requestId}
          );

          await sendEvent({
            kind:"body",
            ...base,
            response_body:body.body || "",
            response_body_base64:!!body.base64Encoded
          });
        } catch (_) {}
      }

      await sendEvent({kind:"loading_finished", ...base});
      requests.delete(requestKey);
    }

    else if (method === "Network.webSocketCreated") {
      websockets.set(socketKey(tabId, params.requestId), redactUrl(params.url));

      await sendEvent({
        kind:"websocket_created",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:redactUrl(params.url),
        initiator:params.initiator || null
      });
    }

    else if (method === "Network.webSocketWillSendHandshakeRequest") {
      const wsurl = websockets.get(socketKey(tabId, params.requestId)) || null;
      await sendEvent({
        kind:"websocket_handshake_request",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:wsurl,
        request_headers:redactHeaders((params.request || {}).headers || {})
      });
    }

    else if (method === "Network.webSocketHandshakeResponseReceived") {
      const wsurl = websockets.get(socketKey(tabId, params.requestId)) || null;
      const resp = params.response || {};
      await sendEvent({
        kind:"websocket_handshake_response",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:wsurl,
        status:resp.status,
        response_headers:redactHeaders(resp.headers || {})
      });
    }

    else if (method === "Network.webSocketFrameSent" ||
             method === "Network.webSocketFrameReceived") {
      const frame = params.response || {};
      await sendEvent({
        kind: method.endsWith("Sent") ? "websocket_sent" : "websocket_received",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:websockets.get(socketKey(tabId, params.requestId)) || null,
        websocket_opcode:frame.opcode,
        websocket_mask:!!frame.mask,
        // CDP supplies opcode=1 as UTF-8 text; all other opcodes are base64.
        websocket_payload_encoding:Number(frame.opcode) === 1 ? "utf8" : "base64",
        websocket_payload:frame.payloadData || ""
      });
    }

    else if (method === "Network.webSocketFrameError") {
      await sendEvent({
        kind:"websocket_error",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:websockets.get(socketKey(tabId, params.requestId)) || null,
        note:params.errorMessage || ""
      });
    }

    else if (method === "Network.webSocketClosed") {
      await sendEvent({
        kind:"websocket_closed",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:`ws:${tabId}:${params.requestId}`,
        resource_type:"WebSocket",
        url:websockets.get(socketKey(tabId, params.requestId)) || null
      });
      websockets.delete(socketKey(tabId, params.requestId));
    }

    else if (method === "Network.eventSourceMessageReceived") {
      const requestKey = currentRequestKey(tabId, params.requestId);
      const base = requests.get(requestKey) || {};
      await sendEvent({
        kind:"sse_message",
        tab_id:tabId,
        request_id:params.requestId,
        request_key:requestKey,
        resource_type:"EventSource",
        url:base.url || null,
        response_body:params.data || "",
        note:params.eventName || ""
      });
    }
  } catch (e) {
    console.warn("Web API Hunter event error", method, e);
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.cmd === "attach") {
      sendResponse(await attachTab(msg.tabId));
    }

    else if (msg.cmd === "detach") {
      sendResponse(await detachTab(msg.tabId));
    }

    else if (msg.cmd === "status") {
      const attached = await actualAttached(msg.tabId);
      if (attached) attachedTabs.add(msg.tabId);
      else attachedTabs.delete(msg.tabId);

      const a = actionByTab[String(msg.tabId)] || {};
      await persistState();

      sendResponse({
        ok:true,
        attached,
        action_active:!!a.active,
        action_name:a.name || ""
      });
    }

    else if (msg.cmd === "marker") {
      if (msg.marker === "start") {
        actionByTab[String(msg.tabId)] = {
          active:true,
          name:msg.note || "Action"
        };
      } else if (msg.marker === "end") {
        actionByTab[String(msg.tabId)] = {
          active:false,
          name:msg.note || "Action"
        };
      }

      await persistState();

      await sendEvent({
        kind:"marker",
        marker:msg.marker,
        note:msg.note || "",
        tab_id:msg.tabId
      });

      sendResponse({ok:true});
    }

    else {
      sendResponse({ok:false, error:"unknown_command"});
    }
  })().catch(err => sendResponse({ok:false, error:String(err)}));

  return true;
});
