// User management page. Talks to the JSON API whose URL the server puts in
// <meta name="ada-users-api">. No framework, no build step.
(() => {
  "use strict";

  // The server may give paths relative to this page ("..") so the page keeps
  // working behind a proxy that strips a path prefix. Resolve them here and
  // drop the trailing slash the routes do not have.
  const resolve = (v) => (v ? new URL(v, location.href).pathname.replace(/\/+$/, "") : "");
  const api = resolve(document.querySelector('meta[name="ada-users-api"]').content);
  const account = resolve(document.querySelector('meta[name="ada-account-api"]')?.content || "");
  const $ = (id) => document.getElementById(id);

  let users = [];
  let roles = [];
  let me = null;
  let editing = null;

  async function call(method, url, body) {
    const res = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: body ? { "Content-Type": "application/json", Accept: "application/json" } : { Accept: "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 204) return null;

    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || data.error || res.statusText);

    return data;
  }

  function can(perm) {
    if (!me) return false;
    return (me.permissions || []).some((p) => p === "*" || p === perm || (p.endsWith("*") && perm.startsWith(p.slice(0, -1))));
  }

  function showError(el, err) {
    el.textContent = err ? String(err.message || err) : "";
    el.hidden = !err;
  }

  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children) node.append(c instanceof Node ? c : document.createTextNode(c ?? ""));
    return node;
  }

  function render() {
    const q = $("filter").value.trim().toLowerCase();
    const rows = $("rows");
    rows.replaceChildren();

    const list = users.filter((u) =>
      !q || [u.username, u.name, u.email, ...(u.roles || [])].some((v) => (v || "").toLowerCase().includes(q)));

    if (list.length === 0) {
      rows.append(el("tr", {}, el("td", { colspan: "5", class: "muted" }, q ? "No matching users." : "No users yet.")));
      return;
    }

    for (const u of list) {
      const who = el("td", {}, u.name || u.username, el("small", {}, [u.username, u.email].filter(Boolean).join(" · ")));
      const chips = el("td", {}, ...(u.roles || []).map((r) => el("span", { class: "chip" }, r)));
      const status = el("td", { class: u.disabled ? "status-off" : "" }, u.disabled ? "Disabled" : "Active");
      const created = el("td", { class: "muted" }, u.created_at ? new Date(u.created_at).toLocaleDateString() : "");
      const edit = el("td", {}, can("users:write") ? el("button", { type: "button", class: "link", onclick: () => open(u) }, "Edit") : "");
      rows.append(el("tr", {}, who, chips, status, created, edit));
    }
  }

  function open(user) {
    editing = user;
    const f = $("form");
    f.reset();
    showError($("form-error"), null);

    $("form-title").textContent = user ? "Edit " + user.username : "New user";
    $("password-label").textContent = user ? "New password (leave empty to keep)" : "Password";
    $("delete").hidden = !user || (me && me.id === user.id);

    f.username.value = user?.username || "";
    f.name.value = user?.name || "";
    f.email.value = user?.email || "";
    f.disabled.checked = !!user?.disabled;
    f.password.required = !user;

    const box = $("roles");
    box.replaceChildren();
    const current = user ? user.roles || [] : ["user"];
    for (const r of roles) {
      box.append(el("label", {},
        el("input", Object.assign({ type: "checkbox", name: "role", value: r.name }, current.includes(r.name) ? { checked: "" } : {})),
        el("span", {}, r.name, " ", el("small", {}, r.description || (r.permissions || []).join(", ")))));
    }

    $("editor").showModal();
    f.username.focus();
  }

  async function save(ev) {
    ev.preventDefault();
    const f = $("form");
    const body = {
      username: f.username.value.trim(),
      name: f.name.value.trim(),
      email: f.email.value.trim(),
      disabled: f.disabled.checked,
      roles: [...f.querySelectorAll('input[name="role"]:checked')].map((i) => i.value),
    };
    if (f.password.value) body.password = f.password.value;

    $("save").disabled = true;
    try {
      if (editing) await call("PATCH", api + "/" + encodeURIComponent(editing.id), body);
      else await call("POST", api, body);
      $("editor").close();
      await load();
    } catch (err) {
      showError($("form-error"), err);
    } finally {
      $("save").disabled = false;
    }
  }

  async function remove() {
    if (!editing || !confirm("Delete " + editing.username + "? This cannot be undone.")) return;
    try {
      await call("DELETE", api + "/" + encodeURIComponent(editing.id));
      $("editor").close();
      await load();
    } catch (err) {
      showError($("form-error"), err);
    }
  }

  async function load() {
    try {
      [users, roles] = await Promise.all([call("GET", api), call("GET", api + "/roles")]);
      showError($("error"), null);
      render();
    } catch (err) {
      showError($("error"), err);
    }
  }

  async function start() {
    if (account) {
      try {
        me = await call("GET", account);
        $("who").textContent = "Signed in as " + (me.name || me.username);
      } catch (_) {
        me = null;
      }
    }

    document.querySelectorAll("[data-needs]").forEach((n) => { n.hidden = !can(n.dataset.needs); });

    $("filter").addEventListener("input", render);
    $("new").addEventListener("click", () => open(null));
    $("cancel").addEventListener("click", () => $("editor").close());
    $("delete").addEventListener("click", remove);
    $("form").addEventListener("submit", save);

    await load();
  }

  start();
})();
