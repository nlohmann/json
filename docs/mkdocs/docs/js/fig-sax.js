/*
 * figures: sax
 *
 * SAX event stepper on features/parsing/sax_interface.md. The page contains the final state as static HTML (input,
 * all nine events, the finished tree); this script adds the controls and redraws the three lanes for each step:
 * the consumed part of the input, the events called so far, and the state of one of two handlers (a DOM builder
 * that keeps a stack of open containers, or a handler that keeps only the value at /b). "return false at this
 * event" stops the parse at the current event: the later events are not called and the rest of the input is not read.
 */
(function () {
    "use strict";

    var SRC = '{"a":[1,true],"b":"x"}';
    // tok: [start, end) of the token that makes the parser call the event
    var EVENTS = [
        { call: "start_object(-1)", cls: "os", tok: [0, 1], op: "so" },
        { call: 'key("a")', cls: "k", tok: [1, 4], op: "key", v: "a" },
        { call: "start_array(-1)", cls: "as", tok: [5, 6], op: "sa" },
        { call: "number_unsigned(1)", cls: "v", tok: [6, 7], op: "val", v: { t: "n", v: "1" } },
        { call: "boolean(true)", cls: "v", tok: [8, 12], op: "val", v: { t: "b", v: "true" } },
        { call: "end_array()", cls: "ae", tok: [12, 13], op: "end" },
        { call: 'key("b")', cls: "k", tok: [14, 17], op: "key", v: "b" },
        { call: 'string("x")', cls: "v", tok: [18, 21], op: "val", v: { t: "s", v: '"x"' } },
        { call: "end_object()", cls: "oe", tok: [21, 22], op: "end" }
    ];
    var N = EVENTS.length;

    function esc(s) {
        return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    // ---- handler A: DOM builder (like json_sax_dom_parser) ----
    function domState(steps) {
        var root = null, stack = [], last = null;
        function place(v) {
            if (!root) { root = v; return; }
            var top = stack[stack.length - 1];
            if (top.t === "a") { top.e.push(v); } else { top.m[top.m.length - 1][1] = v; }
        }
        for (var i = 0; i < steps; ++i) {
            var ev = EVENTS[i], v;
            if (ev.op === "so" || ev.op === "sa") {
                v = ev.op === "so" ? { t: "o", m: [] } : { t: "a", e: [] };
                var top = stack[stack.length - 1];
                v.ptr = !top ? "" : top.ptr + "/" + (top.t === "a" ? top.e.length : top.m[top.m.length - 1][0]);
                place(v); stack.push(v); last = v;
            } else if (ev.op === "key") {
                v = { t: "z", v: "null" };      // the DOM parser adds null at the key and fills it in later
                stack[stack.length - 1].m.push([ev.v, v]); last = v;
            } else if (ev.op === "val") {
                v = { t: ev.v.t, v: ev.v.v }; place(v); last = v;
            } else {
                last = stack.pop();
            }
        }
        return { root: root, stack: stack, last: last };
    }

    function pretty(v, ind, last, out, prefix, suffix) {
        var pad = new Array(ind + 1).join("  ");
        var mark = function (s) { return v === last ? '<span class="nj-sax-hit">' + s + "</span>" : s; };
        if (v.t === "o" || v.t === "a") {
            var items = v.t === "o" ? v.m : v.e, open = v.t === "o" ? "{" : "[", close = v.t === "o" ? "}" : "]";
            if (!items.length) { out.push(pad + prefix + mark(open + close) + suffix); return; }
            out.push(pad + prefix + mark(open));
            for (var i = 0; i < items.length; ++i) {
                var comma = i < items.length - 1 ? "," : "";
                if (v.t === "o") {
                    pretty(items[i][1], ind + 1, last, out, esc('"' + items[i][0] + '": '), comma);
                } else {
                    pretty(items[i], ind + 1, last, out, "", comma);
                }
            }
            out.push(pad + mark(close) + suffix);
        } else {
            out.push(pad + prefix + mark(esc(v.v)) + suffix);
        }
    }

    function renderDom(steps, stopped) {
        var st = domState(steps), lines = [];
        var tree = st.root ? (pretty(st.root, 0, st.last, lines, "", ""), lines.join("\n")) : '<span class="nj-sax-dim">(nothing built yet)</span>';
        var chips = st.stack.length ? st.stack.map(function (c) {
            return '<li><code>' + (c.t === "o" ? "{}" : "[]") + " " + esc(c.ptr === "" ? "root" : c.ptr) + "</code></li>";
        }).join("") : '<li class="nj-sax-dim">empty</li>';
        var note;
        if (steps === 0) { note = "The handler starts with an empty stack."; }
        else if (stopped) { note = "The handler keeps what it built so far; the containers on the stack stay unfinished."; }
        else if (steps === N) { note = "The tree is complete and no container is open. The number of elements is passed as -1: the parser does not know it in advance."; }
        else { note = EVENTS[steps - 1].op === "key" ? "A key adds the member with a null value, which the next value replaces." : "Values go into the container on top of the stack."; }
        return '<pre class="nj-sax__tree"><code>' + tree + "</code></pre>" +
            '<p class="nj-sax__stackh">stack of open containers</p><ol class="nj-sax__stack" reversed>' + chips + "</ol>" +
            '<p class="nj-sax__note">' + note + "</p>";
    }

    // ---- handler B: keep only the value at /b ----
    function renderKeep(steps, stopped) {
        var frames = [], ptr = "", kept = null, keptAt = 0, action = "";
        var where = function () {
            return frames.map(function (f) { return "/" + (f.t === "a" ? f.i : f.k); }).join("");
        };
        for (var i = 0; i < steps; ++i) {
            var ev = EVENTS[i], top = frames[frames.length - 1];
            if (ev.op === "key") { top.k = ev.v; ptr = where(); action = "remembers the key"; continue; }
            if (ev.op === "end") { ptr = frames.pop().loc; action = "leaves the container"; continue; }
            ptr = where();
            action = ptr === "/b" ? "keeps it" : "ignores it";
            if (top && top.t === "a") { top.i++; }
            if (ev.op === "so") { frames.push({ t: "o", k: "", loc: ptr }); }
            else if (ev.op === "sa") { frames.push({ t: "a", i: 0, loc: ptr }); }
            else if (ptr === "/b") { kept = ev.v.v; keptAt = i + 1; }
        }
        var note;
        if (steps === 0) { note = "The handler keeps only the current position and, once it is found, one value."; }
        else if (stopped) { note = kept !== null ? "The value is found, so stopping here saves reading the rest of the input." : "Stopped before /b was read: nothing is kept."; }
        else { note = "At " + (ptr === "" ? "the root" : ptr) + " the handler " + action + "."; }
        if (!stopped && steps === keptAt && kept !== null) {
            note += " A handler that needs nothing else could return false here.";
        }
        return '<dl class="nj-sax__kv">' +
            "<dt>position</dt><dd><code>" + (steps ? esc(ptr === "" ? "(root)" : ptr) : "-") + "</code></dd>" +
            "<dt>kept value</dt><dd>" + (kept !== null ? '<code class="' + (steps === keptAt ? "nj-sax-hit" : "") + '">' + esc(kept) + "</code>" : '<span class="nj-sax-dim">none</span>') + "</dd>" +
            "</dl>" +
            '<p class="nj-sax__note">' + note + " No tree is built.</p>";
    }

    function init(root) {
        if (root.getAttribute("data-nj-sax-ready")) { return; }
        root.setAttribute("data-nj-sax-ready", "1");
        var src = root.querySelector(".nj-sax__src");
        var items = root.querySelectorAll(".nj-sax__events li");
        var head = root.querySelector(".nj-sax__lane--state .nj-sax__h");
        var state = root.querySelector(".nj-sax__state");
        var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        var step = 0, mode = "dom", stopAt = 0, timer = null;

        // controls
        var bar = document.createElement("div");
        bar.className = "nj-sax__controls";
        bar.innerHTML =
            '<div class="nj-sax__btns">' +
            '<button type="button" class="nj-sax-btn" data-a="reset" aria-label="Reset to before the first event">Reset</button>' +
            '<button type="button" class="nj-sax-btn" data-a="prev" aria-label="Previous event">Prev</button>' +
            '<button type="button" class="nj-sax-btn nj-sax-btn--main" data-a="play" aria-label="Play all events">Play</button>' +
            '<button type="button" class="nj-sax-btn" data-a="next" aria-label="Next event">Next</button>' +
            "</div>" +
            '<label class="nj-sax__stop"><input type="checkbox" data-a="stop"> return <code>false</code> at this event</label>' +
            '<div class="nj-sax__modes" role="group" aria-label="handler">' +
            '<button type="button" class="nj-sax-btn" data-m="dom" aria-pressed="true">build a tree</button>' +
            '<button type="button" class="nj-sax-btn" data-m="keep" aria-pressed="false">keep only /b</button>' +
            "</div>";
        root.insertBefore(bar, root.firstChild);
        var status = document.createElement("p");
        status.className = "nj-sax__status";
        status.setAttribute("aria-live", "polite");
        root.appendChild(status);
        var btn = function (a) { return bar.querySelector('[data-a="' + a + '"]'); };
        var stopBox = btn("stop");

        function stopped() { return stopAt > 0 && step === stopAt; }

        function render() {
            var end = step ? EVENTS[step - 1].tok[1] : 0, cur = step ? EVENTS[step - 1] : null;
            var html = "";
            if (cur) {
                html += '<span class="nj-sax-read">' + esc(SRC.slice(0, cur.tok[0])) + "</span>";
                html += '<span class="nj-sax-read nj-sax-tok nj-sax-tok--' + cur.cls + '">' + esc(SRC.slice(cur.tok[0], end)) + "</span>";
            }
            html += '<span class="' + (stopped() ? "nj-sax-unread nj-sax-unread--never" : "nj-sax-unread") + '">' + esc(SRC.slice(end)) + "</span>";
            src.innerHTML = html;
            for (var i = 0; i < N; ++i) {
                var li = items[i];
                li.classList.toggle("nj-sax-ev--done", i < step);
                li.classList.toggle("nj-sax-ev--cur", i === step - 1);
                li.classList.toggle("nj-sax-ev--todo", i >= step && !stopped());
                li.classList.toggle("nj-sax-ev--skip", i >= step && stopped());
                li.classList.toggle("nj-sax-ev--false", stopped() && i === step - 1);
                if (i === step - 1) { li.setAttribute("aria-current", "step"); } else { li.removeAttribute("aria-current"); }
            }
            head.innerHTML = mode === "dom" ? "handler: build a value tree, as <code>parse</code> does" : "handler: keep only the value at <code>/b</code>";
            state.innerHTML = mode === "dom" ? renderDom(step, stopped()) : renderKeep(step, stopped());
            bar.querySelectorAll("[data-m]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-m") === mode)); });
            btn("prev").disabled = step === 0;
            btn("reset").disabled = step === 0;
            btn("next").disabled = step === N || stopped();
            stopBox.disabled = step === 0;
            stopBox.checked = stopped();
            var playing = timer !== null;
            btn("play").textContent = playing ? "Pause" : "Play";
            btn("play").setAttribute("aria-label", playing ? "Pause" : "Play all events");
            var msg;
            if (step === 0) { msg = "Before the first event: nothing is read yet."; }
            else if (stopped()) { msg = "Event " + step + " of " + N + ": " + cur.call + " returned false. Parsing stops, sax_parse returns false, and the rest of the input is not read."; }
            else if (step === N) { msg = "Event " + N + " of " + N + ": " + cur.call + ". The input is read completely and sax_parse returns true."; }
            else { msg = "Event " + step + " of " + N + ": the parser read " + SRC.slice(cur.tok[0], cur.tok[1]) + " and called " + cur.call + "."; }
            status.textContent = msg;
        }

        function stop() { if (timer !== null) { clearInterval(timer); timer = null; } }
        function go(s) {
            step = Math.max(0, Math.min(N, s));
            if (stopAt && step < stopAt) { stopAt = 0; }
            render();
        }

        bar.addEventListener("click", function (e) {
            var b = e.target.closest("button");
            if (!b) { return; }
            var m = b.getAttribute("data-m");
            if (m) { mode = m; render(); return; }
            var a = b.getAttribute("data-a");
            if (a === "play") {
                if (timer !== null) { stop(); render(); return; }
                if (step === N || stopped()) { stopAt = 0; step = 0; }
                timer = setInterval(function () {
                    if (step >= N || stopped()) { stop(); render(); return; }
                    go(step + 1);
                    if (step >= N) { stop(); render(); }
                }, reduce ? 1400 : 900);
                go(step + 1);
                return;
            }
            stop();
            if (a === "reset") { stopAt = 0; go(0); }
            else if (a === "prev") { go(step - 1); }
            else if (a === "next") { go(step + 1); }
        });
        stopBox.addEventListener("change", function () {
            stop();
            stopAt = stopBox.checked ? step : 0;
            render();
        });
        root.classList.add("nj-sax--live");
        render();
    }

    function setup() {
        document.querySelectorAll("[data-nj-sax]").forEach(init);
    }

    if (typeof window.document$ !== "undefined" && window.document$ && typeof window.document$.subscribe === "function") {
        window.document$.subscribe(setup);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", setup);
    } else {
        setup();
    }
})();
