/* figures: pointer
 *
 * Two widgets that enhance static markup (the markup alone is a complete, readable figure):
 *   - [data-nj-pointer-walk] in features/json_pointer.md: a tree of the example document plus a pointer bar whose
 *     segments select a prefix of the pointer; the path down to that level is highlighted and its value is shown.
 *   - [data-nj-patch] in features/json_patch.md: a stepper through six JSON Patch operations; the static table of the
 *     operations is hidden once the stepper is built.
 * Initialised through Material's document$ (navigation.instant), idempotent per element.
 */
(function () {
    "use strict";

    function el(tag, cls, html) {
        var e = document.createElement(tag);
        if (cls) e.className = cls;
        if (html !== undefined) e.innerHTML = html;
        return e;
    }
    function esc(s) {
        return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    /* ---------- JSON Pointer walker ---------- */

    var PRESETS = ["", "/array", "/array/0", "/array/1", "/array/2", "/nested", "/nested/one", "/nested/two",
        "/nested/three", "/nested/three/0", "/nested/three/1", "/"];

    function tokens(ptr) {
        if (ptr === "") return [];
        return ptr.slice(1).split("/").map(function (t) { return t.replace(/~1/g, "/").replace(/~0/g, "~"); });
    }
    function joinTokens(toks) {
        return toks.map(function (t) { return "/" + t.replace(/~/g, "~0").replace(/\//g, "~1"); }).join("");
    }
    // RFC 6901 resolution as json::at() does it; returns {ok, value, depth, error}
    function resolve(doc, toks) {
        var v = doc;
        for (var i = 0; i < toks.length; ++i) {
            var t = toks[i];
            if (Array.isArray(v)) {
                if (!/^(0|[1-9][0-9]*)$/.test(t) || Number(t) >= v.length) {
                    return { ok: false, depth: i, error: "at() throws out_of_range: array index '" + t + "' is out of range" };
                }
                v = v[Number(t)];
            } else if (v !== null && typeof v === "object") {
                if (!Object.prototype.hasOwnProperty.call(v, t)) {
                    return { ok: false, depth: i, error: "at() throws out_of_range.403: key '" + t + "' not found" };
                }
                v = v[t];
            } else {
                return { ok: false, depth: i, error: "a primitive value has no children" };
            }
        }
        return { ok: true, value: v, depth: toks.length };
    }
    function ptrLabel(p) { return p === "" ? '""' : p; }

    function initWalk(root) {
        if (root.dataset.njReady) return;
        var doc;
        try { doc = JSON.parse(root.getAttribute("data-doc")); } catch (e) { return; }
        root.dataset.njReady = "1";
        root.classList.add("nj-pointer-walk--js");

        var tree = root.querySelector(".nj-pointer-tree");
        var items = Array.prototype.slice.call(tree.querySelectorAll("li[data-p]"));
        var state = { ptr: "/nested/three/1", level: 3 };

        // tree labels become buttons that select their own pointer
        items.forEach(function (li) {
            var span = li.querySelector(":scope > .nj-pointer-n");
            var b = el("button", "nj-pointer-n", span.innerHTML);
            b.type = "button";
            var p = li.getAttribute("data-p");
            b.setAttribute("aria-label", "Select the pointer " + ptrLabel(p));
            b.addEventListener("click", function () { set(p, tokens(p).length); });
            span.replaceWith(b);
        });

        var panel = el("div", "nj-pointer-panel");
        panel.appendChild(el("div", "nj-pointer-lbl", "Pointer <span>(select a segment)</span>"));
        var bar = el("div", "nj-pointer-bar");
        bar.setAttribute("role", "group");
        bar.setAttribute("aria-label", "Pointer segments");
        panel.appendChild(bar);
        var out = el("div", "nj-pointer-out");
        out.setAttribute("aria-live", "polite");
        panel.appendChild(out);
        panel.appendChild(el("div", "nj-pointer-lbl", "Examples"));
        var presets = el("div", "nj-pointer-presets");
        presets.setAttribute("role", "group");
        presets.setAttribute("aria-label", "Example pointers");
        PRESETS.forEach(function (p) {
            var b = el("button", "nj-pointer-chip", "<code>" + esc(ptrLabel(p)) + "</code>");
            b.type = "button";
            b.setAttribute("data-p", p);
            b.setAttribute("aria-label", p === "" ? "Pointer \"\" (the whole document)" : "Pointer " + p);
            b.addEventListener("click", function () { set(p, tokens(p).length); });
            presets.appendChild(b);
        });
        panel.appendChild(presets);
        var stat = root.querySelector(".nj-pointer-static");
        if (stat) stat.hidden = true;
        root.insertBefore(panel, root.firstChild);

        function liFor(p) {
            for (var i = 0; i < items.length; ++i) if (items[i].getAttribute("data-p") === p) return items[i];
            return null;
        }

        function render() {
            var toks = tokens(state.ptr);
            var sel = toks.slice(0, state.level);
            var r = resolve(doc, sel);

            // bar: root chip plus one button per reference token
            bar.innerHTML = "";
            var parts = [{ label: '""', text: "root", n: 0 }];
            toks.forEach(function (t, i) { parts.push({ label: joinTokens([t]), n: i + 1 }); });
            parts.forEach(function (part) {
                var b = el("button", "nj-pointer-seg" + (part.n === 0 ? " nj-pointer-seg--root" : ""),
                    part.n === 0 ? "<code>\"\"</code>" : "<code>" + esc(part.label) + "</code>");
                b.type = "button";
                b.setAttribute("aria-pressed", part.n === state.level ? "true" : "false");
                if (part.n > state.level) b.classList.add("is-after");
                var prefix = joinTokens(toks.slice(0, part.n));
                b.setAttribute("aria-label", "Go to level " + part.n + ": " + ptrLabel(prefix) + (part.n === 0 ? " (the whole document)" : ""));
                b.addEventListener("click", function () { state.level = part.n; render(); focusSeg(part.n); });
                bar.appendChild(b);
            });

            // tree highlight
            items.forEach(function (li) { li.classList.remove("is-on", "is-target", "is-pass", "is-miss"); });
            var depth = r.ok ? sel.length : r.depth;
            for (var d = 0; d <= depth; ++d) {
                var li = liFor(joinTokens(sel.slice(0, d)));
                if (!li) break;
                li.classList.add("is-on");
                if (d > 0) {
                    for (var s = li.previousElementSibling; s; s = s.previousElementSibling) s.classList.add("is-pass");
                }
                if (r.ok && d === depth) li.classList.add("is-target");
            }
            if (!r.ok) {
                var miss = liFor(joinTokens(sel.slice(0, r.depth)));
                if (miss) miss.classList.add("is-miss");
            }

            var shown = joinTokens(sel);
            out.innerHTML = r.ok
                ? "<code>" + esc(ptrLabel(shown)) + "</code> resolves to <code class=\"nj-pointer-val\">" + esc(JSON.stringify(r.value)) + "</code>" +
                  (shown === "" ? " <span class=\"nj-pointer-note\">(the whole document)</span>" : "")
                : "<code>" + esc(ptrLabel(shown)) + "</code> <span class=\"nj-pointer-err\">identifies no value</span>: " + esc(r.error) +
                  ". <span class=\"nj-pointer-note\">The token after <code>/</code> is the empty key, and the document has none.</span>";

            Array.prototype.forEach.call(presets.children, function (b) {
                b.setAttribute("aria-pressed", b.getAttribute("data-p") === shown && state.level === tokens(state.ptr).length ? "true" : "false");
            });
        }
        function focusSeg(n) {
            var b = bar.children[n];
            if (b) b.focus();
        }
        function set(p, level) {
            state.ptr = p;
            state.level = level;
            render();
        }
        render();
    }

    /* ---------- JSON Patch stepper ---------- */

    function k(s) { return '<span class="nj-patch-k">"' + s + '"</span>'; }
    function s(v) { return '<span class="nj-patch-s">"' + v + '"</span>'; }
    function ins(x) { return '<span class="nj-patch-ins">' + x + "</span>"; }
    function src(x) { return '<span class="nj-patch-src">' + x + "</span>"; }
    var I = "  ";

    var OPS = [
        { op: "replace", path: "/baz", extra: ', "value": "boo"' },
        { op: "add", path: "/hello", extra: ', "value": ["world"]' },
        { op: "remove", path: "/foo", extra: "" },
        { op: "move", from: "/baz", path: "/hello/1", extra: "" },
        { op: "copy", from: "/hello/0", path: "/greeting", extra: "" },
        { op: "test", path: "/greeting", extra: ', "value": "world"' }
    ];
    // each frame: document lines [html, line class, note], optional connector {from, to}, status text
    var FRAMES = [
        { lines: [["{"], [I + k("baz") + ": " + s("qux") + ","], [I + k("foo") + ": " + s("bar")], ["}"]],
          status: "Start: the original document of the example below. Press Next to apply the first operation." },
        { lines: [["{"], [I + k("baz") + ": " + s("qux") + ",", "del"], [I + k("baz") + ": " + s("boo") + ",", "add", "replaced"],
                  [I + k("foo") + ": " + s("bar")], ["}"]],
          status: "replace /baz: the value \"qux\" is replaced by \"boo\"." },
        { lines: [["{"], [I + k("baz") + ": " + s("boo") + ","], [I + k("foo") + ": " + s("bar") + ","],
                  [I + k("hello") + ": [" + s("world") + "]", "add", "added"], ["}"]],
          status: "add /hello: the new member \"hello\" with the value [\"world\"] is added." },
        { lines: [["{"], [I + k("baz") + ": " + s("boo") + ","], [I + k("foo") + ": " + s("bar") + ",", "del", "removed"],
                  [I + k("hello") + ": [" + s("world") + "]"], ["}"]],
          status: "remove /foo: the member \"foo\" is removed. This is the result of the example below." },
        { lines: [["{"], [I + k("baz") + ": " + s("boo") + ",", "del", "moved"],
                  [I + k("hello") + ": [" + s("world") + ", " + ins(s("boo")) + "]", "mod", "from /baz"], ["}"]],
          arc: { from: 1, to: 2 },
          status: "move from /baz to /hello/1: \"boo\" is removed from /baz and inserted into the array at index 1." },
        { lines: [["{"], [I + k("greeting") + ": " + s("world") + ",", "add", "copy of /hello/0"],
                  [I + k("hello") + ": [" + src(s("world")) + ", " + s("boo") + "]"], ["}"]],
          arc: { from: 2, to: 1 },
          status: "copy from /hello/0 to /greeting: the value \"world\" is copied to the new member \"greeting\"." },
        { lines: [["{"], [I + k("greeting") + ": " + s("world") + ",", "test", "test passed"],
                  [I + k("hello") + ": [" + s("world") + ", " + s("boo") + "]"], ["}"]],
          status: "test /greeting: the value equals \"world\", so the document is unchanged. A failed test would make patch() throw other_error 501." }
    ];

    function opHtml(o) {
        var h = '{"op": "<span class="nj-patch-op">' + o.op + '</span>"';
        if (o.from) h += ', "from": "<span class="nj-patch-path">' + o.from + '</span>"';
        h += ', "path": "<span class="nj-patch-path">' + o.path + '</span>"' + esc(o.extra) + "}";
        return h;
    }

    function initPatch(root) {
        if (root.dataset.njReady) return;
        root.dataset.njReady = "1";
        root.classList.add("nj-patch--js");
        var step = 0;

        var stage = el("div", "nj-patch-stage");
        var cols = el("div", "nj-patch-cols");
        var left = el("div", "nj-patch-col");
        left.appendChild(el("div", "nj-patch-h", "Document"));
        var docBox = el("div", "nj-patch-doc");
        left.appendChild(docBox);
        var right = el("div", "nj-patch-col");
        right.appendChild(el("div", "nj-patch-h", "Patch"));
        var list = el("ol", "nj-patch-ops");
        OPS.forEach(function (o) { list.appendChild(el("li", "", "<code>" + opHtml(o) + "</code>")); });
        right.appendChild(list);
        cols.appendChild(left);
        cols.appendChild(right);
        stage.appendChild(cols);
        // controls and status sit under the document, so on a phone both stay in view together

        var ctrl = el("div", "nj-patch-ctrl");
        function btn(label, aria, fn) {
            var b = el("button", "nj-patch-btn", label);
            b.type = "button";
            b.setAttribute("aria-label", aria);
            b.addEventListener("click", fn);
            ctrl.appendChild(b);
            return b;
        }
        var bReset = btn("Reset", "Back to the original document", function () { step = 0; render(true); });
        var bPrev = btn("Back", "Previous operation", function () { if (step > 0) { step--; render(true); } });
        var bNext = btn("Next", "Apply the next operation", function () { if (step < OPS.length) { step++; render(true); } });
        bNext.classList.add("nj-patch-btn--primary");
        var count = el("span", "nj-patch-count");
        ctrl.appendChild(count);
        left.appendChild(ctrl);
        var status = el("p", "nj-patch-status");
        status.setAttribute("aria-live", "polite");
        left.appendChild(status);
        root.insertBefore(stage, root.firstChild);

        function render(animate) {
            var f = FRAMES[step];
            docBox.innerHTML = "";
            f.lines.forEach(function (ln) {
                var row = el("div", "nj-patch-line" + (ln[1] ? " nj-patch-line--" + ln[1] : ""));
                row.appendChild(el("span", "nj-patch-code", ln[0]));
                if (ln[2]) row.appendChild(el("span", "nj-patch-note", esc(ln[2])));
                docBox.appendChild(row);
            });
            if (f.arc) {
                var a = el("div", "nj-patch-arc " + (f.arc.to > f.arc.from ? "nj-patch-arc--down" : "nj-patch-arc--up"));
                var top = Math.min(f.arc.from, f.arc.to), n = Math.abs(f.arc.to - f.arc.from);
                a.style.top = "calc(var(--nj-patch-pad) + " + (top + 0.5) + " * var(--nj-patch-lh))";
                a.style.height = "calc(" + n + " * var(--nj-patch-lh))";
                a.setAttribute("aria-hidden", "true");
                docBox.appendChild(a);
            }
            docBox.classList.toggle("nj-patch-doc--anim", !!animate);
            Array.prototype.forEach.call(list.children, function (li, i) {
                li.className = i + 1 === step ? "is-cur" : (i + 1 < step ? "is-done" : "");
                if (i + 1 === step) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
            });
            bPrev.disabled = step === 0;
            bReset.disabled = step === 0;
            bNext.disabled = step === OPS.length;
            count.textContent = "Step " + step + " of " + OPS.length;
            status.textContent = f.status;
        }
        render(false);
    }

    function init() {
        Array.prototype.forEach.call(document.querySelectorAll("[data-nj-pointer-walk]"), initWalk);
        Array.prototype.forEach.call(document.querySelectorAll("[data-nj-patch]"), initPatch);
    }
    if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
        window.document$.subscribe(init);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
