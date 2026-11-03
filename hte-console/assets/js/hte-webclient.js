// HTE Remote's web client: hands the bundle its configuration (window.__RD__) and, for a signed-in person, shows the computers
// they may reach right now (GET /webclient/devices; the bundle has no list of its own) and connects to a clicked one without
// asking for a password, as the desktop client does. The ID field stays below the list as the secondary way in, with no
// suggestions and no history; an ID outside the person's reach gets no password. The password box stays, collapsed, for a
// computer with no kept password or a manual override. The bundle itself is not changed: this fills the
// box it already reads and presses its Connect button. A password is never logged and never kept past that click.
(function () {
    "use strict";
    var holder = document.getElementById("rd-config");
    var cfg = {};
    try { cfg = JSON.parse(holder.getAttribute("data-config") || "{}"); } catch (e) { cfg = {}; }
    window.__RD__ = cfg;
    holder.removeAttribute("data-config");
    if (!cfg.hteCredentialUrl) { return; }

    var manual = false;      // the person opened the box themself: what they type wins
    var passThrough = false; // our own re-click
    var usedManaged = false;
    var el = {};

    function fetchCredential(id) {
        return fetch(cfg.hteCredentialUrl, {
            method: "POST",
            credentials: "same-origin",
            cache: "no-store",
            headers: { "Content-Type": "application/x-www-form-urlencoded", "X-CSRF-TOKEN": cfg.hteCsrf || "", "Accept": "application/json" },
            body: "id=" + encodeURIComponent(id)
        }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) { return j && j.password ? String(j.password) : ""; }).catch(function () { return ""; });
    }

    function expand(note) {
        el.box.classList.remove("hte-collapsed");
        el.row.classList.remove("hte-collapsed-row");
        el.save.classList.remove("hte-hidden");
        el.toggle.hidden = true;
        manual = true;
        if (note) { el.help.textContent = note; }
        el.pw.focus();
    }

    function currentId() {
        var typed = el.peer && el.peer.value ? el.peer.value : (cfg.peerId || "");
        return String(typed).replace(/\s+/g, "");
    }

    function onConnect(ev) {
        if (passThrough || manual || el.pw.value) { return; }
        var id = currentId();
        if (!id) { return; }
        ev.stopImmediatePropagation();
        ev.preventDefault();
        el.btn.disabled = true;
        fetchCredential(id).then(function (pw) {
            el.btn.disabled = false;
            if (!pw) {
                expand("No password is kept for this computer, or it is not one you can reach. Enter its password.");
                return;
            }
            usedManaged = true;
            el.pw.value = pw;
            el.save.querySelector("input").checked = false;
            passThrough = true;
            try { el.btn.click(); } finally { passThrough = false; }
        });
    }

    function onEnter(ev) {
        if (ev.key === "Enter") { onConnect(ev); }
    }

    function text(tag, cls, t) {
        var n = document.createElement(tag);
        if (cls) { n.className = cls; }
        if (t !== undefined) { n.textContent = t; }
        return n;
    }

    // the person's computers above the ID field; a click fills the field the bundle reads and presses Connect
    function buildList() {
        var field = document.getElementById("rd-field-id");
        if (!cfg.hteDevicesUrl || !field || cfg.peerId) { return; }
        var wrap = text("div", "hte-devices");
        var head = text("div", "hte-devices-head", "Your computers");
        var list = text("div", "hte-devices-list");
        list.setAttribute("role", "list");
        wrap.appendChild(head);
        wrap.appendChild(list);
        var other = text("div", "hte-devices-other", "Or connect by computer ID");
        field.insertAdjacentElement("beforebegin", wrap);
        field.insertAdjacentElement("beforebegin", other);
        el.peer.setAttribute("autocomplete", "off");
        el.peer.setAttribute("autocorrect", "off");

        function render(devices) {
            list.textContent = "";
            if (!devices.length) {
                list.appendChild(text("div", "hte-devices-empty", "No computers are available to you yet."));
                return;
            }
            devices.forEach(function (d) {
                var b = text("button", "hte-device");
                b.type = "button";
                b.setAttribute("role", "listitem");
                var dot = text("span", "hte-dot" + (d.online ? " hte-on" : ""));
                dot.title = d.online ? "Online" : "Offline";
                var body = text("span", "hte-device-body");
                body.appendChild(text("span", "hte-device-name", d.name || d.id));
                body.appendChild(text("span", "hte-device-sub", d.id + (d.os ? " \u00b7 " + d.os : "")));
                b.appendChild(dot);
                b.appendChild(body);
                b.addEventListener("click", function () {
                    if (el.btn.disabled) { return; }
                    el.peer.value = d.id;
                    el.btn.click();
                });
                list.appendChild(b);
            });
        }
        function load() {
            if (document.hidden) { return; }
            fetch(cfg.hteDevicesUrl, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (j) { if (j && Array.isArray(j.devices)) { render(j.devices); } })
                .catch(function () {});
        }
        load();
        setInterval(load, 30000);
        document.addEventListener("visibilitychange", load);
    }

    function setup() {
        el.pw = document.getElementById("rd-password");
        el.btn = document.getElementById("rd-connect");
        el.peer = document.getElementById("rd-peer-id");
        if (!el.pw || !el.btn) { return false; }
        el.box = el.pw.closest(".rd-input");
        el.row = el.pw.closest(".rd-connect-row");
        el.save = document.querySelector(".rd-save");
        el.help = document.querySelector(".rd-help");
        el.box.classList.add("hte-collapsed");
        el.row.classList.add("hte-collapsed-row");
        el.save.classList.add("hte-hidden");
        el.help.textContent = "You are signed in. Pick one of your computers: it connects without a password.";
        el.toggle = document.createElement("button");
        el.toggle.type = "button";
        el.toggle.className = "hte-pw-toggle";
        el.toggle.textContent = "Use a different password";
        el.toggle.addEventListener("click", function () { expand(); });
        el.row.insertAdjacentElement("afterend", el.toggle);
        buildList();
        el.btn.addEventListener("click", onConnect, true);
        el.peer.addEventListener("keydown", onEnter, true);
        // a 2FA code is asked for in place of the password row: the toggle belongs to the password row
        new MutationObserver(function () { el.toggle.style.display = el.row.hidden ? "none" : ""; }).observe(el.row, { attributes: true, attributeFilter: ["hidden"] });
        // a failed login with the kept password: show the box so the person can type another
        var err = document.getElementById("rd-overlay-error");
        if (err) {
            new MutationObserver(function () { if (!err.hidden && usedManaged) { usedManaged = false; expand(); } }).observe(err, { attributes: true, attributeFilter: ["hidden"] });
        }
        // opened with ?id=: connect at once unless the bundle already started (a hash it kept on this device)
        if (cfg.peerId) {
            setTimeout(function () { if (!el.btn.disabled) { el.btn.click(); } }, 150);
        }
        return true;
    }

    var tries = 0;
    (function wait() {
        if (setup()) { return; }
        if (++tries < 200) { setTimeout(wait, 50); }
    })();
})();
