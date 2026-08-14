async function currentTab() {
  const tabs = await chrome.tabs.query({active:true,currentWindow:true});
  return tabs[0];
}

async function send(cmd, extra={}) {
  const tab = await currentTab();
  return await chrome.runtime.sendMessage({cmd, tabId:tab.id, ...extra});
}

function setAction(active, name="") {
  const el = document.getElementById("actionState");
  if (active) {
    el.textContent = "ACTION ACTIVE: " + (name || "Action");
    el.className = "action active";
  } else {
    el.textContent = "Action window idle";
    el.className = "action idle";
  }
}

async function refresh() {
  const tab = await currentTab();
  document.getElementById("tabTitle").textContent =
    tab.title || tab.url || "Current tab";

  const s = await chrome.runtime.sendMessage({
    cmd:"status",
    tabId:tab.id
  });

  document.getElementById("status").textContent =
    s.attached ? "Capturing this tab" : "Not capturing";

  setAction(!!s.action_active, s.action_name || "");
  if (s.action_name) {
    document.getElementById("actionName").value = s.action_name;
  }
}

document.getElementById("attach").onclick = async () => {
  try {
    const r = await send("attach");
    if (!r.ok) alert(r.error);
  } catch(e) {
    alert(String(e));
  }
  refresh();
};

document.getElementById("detach").onclick = async () => {
  try {
    const r = await send("detach");
    if (!r.ok) alert(r.error);
  } catch(e) {
    alert(String(e));
  }
  refresh();
};

document.getElementById("markStart").onclick = async () => {
  const note = document.getElementById("actionName").value || "Action";
  const r = await send("marker",{marker:"start",note});
  if (!r.ok) alert(r.error || "MARK START failed");
  setAction(true,note);
};

document.getElementById("markEnd").onclick = async () => {
  const note = document.getElementById("actionName").value || "Action";
  const r = await send("marker",{marker:"end",note});
  if (!r.ok) alert(r.error || "MARK END failed");
  setAction(false,note);
};

refresh();
