const api = async (url, options = {}) => {
  const headers = {...(options.headers || {}), "X-CSRF-Token": window.TRUSTVAULT.csrf};
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  const response = await fetch(url, {...options, headers});
  if (response.status === 401) { location.href = "/"; throw new Error("Please sign in again."); }
  const body = response.status === 204 ? {} : await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "The request could not be completed.");
  return body;
};

const toast = (message) => {
  const node = document.querySelector("#toast");
  node.textContent = message;
  node.classList.add("visible");
  setTimeout(() => node.classList.remove("visible"), 2800);
};

const readableSize = (bytes) => bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;

async function loadDocuments() {
  const query = new URLSearchParams();
  for (const [key, id] of [["name", "filter-name"], ["owner", "filter-owner"], ["category", "filter-category"], ["from", "filter-from"], ["to", "filter-to"]]) {
    const value = document.getElementById(id).value;
    if (value) query.set(key, value);
  }
  try {
    const {documents} = await api(`/api/documents?${query}`);
    const tbody = document.querySelector("#documents");
    tbody.innerHTML = "";
    document.querySelector("#empty").classList.toggle("hidden", documents.length !== 0);
    for (const doc of documents) {
      const row = document.createElement("tr");
      row.innerHTML = `<td><button class="doc-name" data-open="${doc.id}"><span class="file-icon">▧</span><span>${escapeHtml(doc.name)}<small>${readableSize(doc.size_bytes)}</small></span></button></td>
        <td><span class="category">${escapeHtml(doc.category)}</span></td><td>${escapeHtml(doc.owner)}</td>
        <td><span class="access-dot"></span>${doc.permission === "edit" ? "Can edit" : doc.permission === "read" ? "Read only" : doc.permission === "admin_metadata" ? "Metadata only" : "No access"}</td>
        <td>${new Date(doc.created_at).toLocaleDateString()}</td><td><button class="icon-button" aria-label="Open document" data-open="${doc.id}">···</button></td>`;
      tbody.append(row);
    }
  } catch (error) { toast(error.message); }
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

async function openDocument(id) {
  try {
    const {document: doc, grants} = await api(`/api/documents/${id}`);
    const content = document.querySelector("#detail-content");
    content.innerHTML = `<div class="dialog-title"><div><p class="eyebrow">DOCUMENT DETAILS</p><h2>${escapeHtml(doc.name)}</h2></div><button class="text-button close" data-close>✕</button></div>
      <p class="muted">${escapeHtml(doc.category)} · Owned by ${escapeHtml(doc.owner_name)}</p>
      <div class="detail-actions">${doc.permission === "admin_metadata" ? `<p class="metadata-notice">File contents are protected. Ask the owner for an explicit read grant to download this file.</p>` : `<a class="button primary" href="/api/documents/${id}/download">↓ &nbsp; Download</a>`}
      ${doc.permission === "edit" ? `<button class="button outline" id="edit-document">Edit details</button>` : ""}</div>
      ${doc.permission !== "admin_metadata" ? `<section class="review-tools"><button class="button outline" id="review-document">◈ &nbsp; Review document privacy</button><p class="muted">Local pattern checks only. The file is not sent to an AI service.</p><div id="review-result"></div></section>` : ""}
      ${grants.length ? `<section class="grant-list"><h3>People with access</h3>${grants.map(g => `<div class="grant"><span>${escapeHtml(g.display_name)} <small>${escapeHtml(g.username)}</small></span><span>${escapeHtml(g.permission)}</span>${window.TRUSTVAULT.role === "owner" ? `<button data-revoke="${escapeHtml(g.username)}" class="text-button danger">Revoke</button>` : ""}</div>`).join("")}</section>` : ""}
      ${window.TRUSTVAULT.role === "owner" ? `<form id="grant-form" class="grant-form"><h3>Grant access &amp; notify</h3><select name="username" required></select><select name="permission"><option value="read">Read only</option><option value="edit">Can edit</option></select><label class="notify-option"><input name="notify" type="checkbox" checked><span>Email the recipient about this grant</span></label><button class="button primary">Grant access</button></form><button class="text-button danger delete-document" id="delete-document">Delete document</button>` : ""}`;
    document.querySelector("#detail-dialog").showModal();
    if (doc.permission !== "admin_metadata") {
      content.querySelector("#review-document").addEventListener("click", async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        button.textContent = "Reviewing document…";
        try {
          const result = await api(`/api/documents/${id}/review`, {method: "POST", body: JSON.stringify({})});
          showReview(content.querySelector("#review-result"), result.report, id);
        } catch (error) {
          toast(error.message);
        } finally {
          button.disabled = false;
          button.innerHTML = "◈ &nbsp; Review document privacy";
        }
      });
      try {
        const result = await api(`/api/documents/${id}/review/latest`);
        showReview(content.querySelector("#review-result"), result.report, id);
      } catch (error) {
        if (error.message !== "no_review_found") toast(error.message);
      }
    }
    if (window.TRUSTVAULT.role === "owner") {
      const {users} = await api("/api/users");
      const select = content.querySelector('select[name="username"]');
      select.innerHTML = users.map(u => `<option value="${escapeHtml(u.username)}">${escapeHtml(u.display_name)} · ${escapeHtml(u.email || "No email registered")}</option>`).join("");
      content.querySelector("#grant-form").addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        try {
          const result = await api(`/api/documents/${id}/permissions`, {
            method: "POST",
            body: JSON.stringify({
              username: form.get("username"),
              permission: form.get("permission"),
              notify: form.get("notify") === "on"
            })
          });
          if (result.notification.status === "failed") {
            toast(result.notification.error);
          } else if (result.notification.sent) {
            toast("Access granted and notification email sent.");
          } else {
            toast("Access granted. No email notification was requested.");
          }
          openDocument(id);
        }
        catch (error) { toast(error.message); }
      });
      content.querySelectorAll("[data-revoke]").forEach(button => button.addEventListener("click", async () => {
        try { await api(`/api/documents/${id}/permissions/${encodeURIComponent(button.dataset.revoke)}`, {method: "DELETE"}); toast("Access revoked immediately."); openDocument(id); }
        catch (error) { toast(error.message); }
      }));
      content.querySelector("#delete-document").addEventListener("click", async () => {
        if (!confirm("Delete this document? It will no longer be available to anyone.")) return;
        try { await api(`/api/documents/${id}`, {method: "DELETE"}); document.querySelector("#detail-dialog").close(); toast("Document deleted."); loadDocuments(); }
        catch (error) { toast(error.message); }
      });
    }
    content.querySelector("#edit-document")?.addEventListener("click", async () => {
      const name = prompt("Document name", doc.name);
      if (name === null) return;
      const category = prompt("Category", doc.category);
      if (category === null) return;
      try { await api(`/api/documents/${id}`, {method: "PATCH", body: JSON.stringify({name, category})}); toast("Document details updated."); openDocument(id); loadDocuments(); }
      catch (error) { toast(error.message); }
    });
  } catch (error) { toast(error.message); }
}

function showReview(container, report, documentId) {
  const findings = report.findings.length
    ? `<ul class="review-findings">${report.findings.map(item =>
      `<li><b>${escapeHtml(item.label)}</b> · ${escapeHtml(item.severity)} · ${item.count} match(es)<small>${item.examples.map(escapeHtml).join(", ")}</small></li>`
    ).join("")}</ul>`
    : `<p class="muted">No supported patterns were detected.</p>`;
  container.innerHTML = `<div class="review-card"><div class="review-score ${escapeHtml(report.risk_level)}"><span>${report.privacy_score}</span><small>/100 privacy score · ${escapeHtml(report.risk_level)} risk</small></div>
    <div><b>${escapeHtml(report.summary)}</b><p class="muted">Reviewed ${new Date(report.created_at).toLocaleString()}</p></div>
    ${findings}<p class="review-disclaimer">${escapeHtml(report.methodology)}</p>
    <a class="text-button" href="/api/documents/${encodeURIComponent(documentId)}/review/latest.pdf">↓ Download PDF report</a></div>`;
}

document.querySelector("#search").addEventListener("click", loadDocuments);
document.querySelector("#filter-name").addEventListener("keydown", event => { if (event.key === "Enter") loadDocuments(); });
document.querySelector("#upload-open")?.addEventListener("click", () => document.querySelector("#upload-dialog").showModal());
document.addEventListener("click", event => {
  const closeButton = event.target.closest("[data-close]");
  closeButton?.closest("dialog")?.close();
});
document.querySelector("#documents").addEventListener("click", event => {
  const button = event.target.closest("[data-open]");
  if (button) openDocument(button.dataset.open);
});
document.querySelector("#upload-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const result = await api("/api/documents", {method: "POST", body: form});
    document.querySelector("#upload-dialog").close();
    event.currentTarget.reset();
    toast("Document uploaded securely.");
    loadDocuments();
  } catch (error) { document.querySelector("#upload-error").textContent = error.message; }
});
async function toggleActivity(event) {
  event.preventDefault();
  const panel = document.querySelector("#activity");
  panel.classList.toggle("hidden");
  if (panel.classList.contains("hidden")) return;
  try {
    const {events, chain_valid} = await api("/api/admin/audit");
    const status = document.querySelector("#chain-status");
    status.textContent = chain_valid ? "✓ Audit chain verified" : "⚠ Audit chain invalid";
    status.className = `badge ${chain_valid ? "success" : "warning"}`;
    document.querySelector("#activity-events").innerHTML = events.map(item => `<div class="event-row"><time>${new Date(item.occurred_at).toLocaleString()}</time><b>${escapeHtml(item.action)}</b><span>${escapeHtml(item.username || "Anonymous")}</span><small>${escapeHtml(item.document_id || item.details)}</small></div>`).join("");
  } catch (error) { toast(error.message); }
}
document.querySelector("#activity-link")?.addEventListener("click", toggleActivity);
document.querySelector("#activity-open")?.addEventListener("click", toggleActivity);
loadDocuments();
