/* figures: macro chooser for the NLOHMANN_DEFINE_TYPE_* / NLOHMANN_DEFINE_DERIVED_TYPE_* macros.
   Usage: <div class="nj-macro-chooser" data-variant="full|compact" data-preset="base=yes,keys=custom" markdown>
   with a static fallback list inside (shown without JavaScript). Links marked with { data-nj-mc="KEY" } in the
   fallback are reused for the reference links, so each embedding page resolves its own relative URLs. Keys:
   intrusive, non_intrusive, derived, with_names, third_party, non_default.
   The rules follow include/nlohmann/detail/macro_scope.hpp: WITH_NAMES takes "key", member pairs and no empty
   member list; WITH_DEFAULT and the plain variants default-construct the type in from_json/get; ONLY_SERIALIZE
   generates to_json only; DERIVED_TYPE calls the base type's to_json/from_json first; at most 63 members (31 with
   WITH_NAMES). The generated programs were compiled and run with clang++ -std=c++11 against include/. */
(function () {
    "use strict";

    var QUESTIONS = [
        { id: "edit", legend: "Can you edit the class?", options: [["yes", "Yes"], ["no", "No, it is third-party"]] },
        { id: "access", legend: "Member access", options: [["public", "All public"], ["private", "Some private"]] },
        { id: "base", legend: "Base class", options: [["no", "None"], ["yes", "Derived from a base"]] },
        { id: "dir", legend: "Direction", options: [["both", "To and from JSON"], ["to", "Only to JSON"]] },
        { id: "missing", legend: "Missing keys when parsing", options: [["throw", "Throw"], ["default", "Keep defaults"]] },
        { id: "keys", legend: "JSON keys", options: [["members", "Member names"], ["custom", "Custom names"]] },
        { id: "ctor", legend: "Default constructible?", options: [["yes", "Yes"], ["no", "No"]] }
    ];

    var KEYWORDS = ("alignas alignof and asm auto bool break case catch char class const constexpr continue decltype default " +
        "delete do double else enum explicit export extern false float for friend goto if inline int long mutable namespace " +
        "new noexcept not nullptr operator or private protected public register return short signed sizeof static " +
        "struct switch template this throw true try typedef typeid typename union unsigned using virtual void volatile " +
        "while").split(" ");
    var HL_TYPES = ["int", "bool", "double", "float", "char", "void", "auto", "unsigned", "long", "short", "signed"];
    var HL_CONST = ["true", "false", "nullptr"];
    var IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
    var MEMBER_TYPE = /^[A-Za-z_][A-Za-z0-9_:<>, ]*$/;

    var counter = 0;

    function el(tag, attrs, text) {
        var e = document.createElement(tag);
        if (attrs) {
            Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
        }
        if (text !== undefined) e.textContent = text;
        return e;
    }

    function esc(s) {
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    /* small C++ tokenizer emitting the Pygments classes the site already colours */
    function highlight(code) {
        var out = "";
        var re = /(\/\/[^\n]*)|(#include)|(<[a-z_/.]+\.hpp>|<[a-z]+>)|("(?:[^"\\\n]|\\.)*")|(\b\d+\b)|([A-Za-z_][A-Za-z0-9_]*)|(::|<<|==|[=:<>&])|([{}()\[\];,.!])|(\s+)|(.)/g;
        var m, prev = "";
        while ((m = re.exec(code)) !== null) {
            var t = m[0];
            if (m[1]) out += '<span class="c1">' + esc(t) + "</span>";
            else if (m[2]) out += '<span class="cp">' + esc(t) + "</span>";
            else if (m[3] && prev === "#include") out += '<span class="cpf">' + esc(t) + "</span>";
            else if (m[4]) out += '<span class="s">' + esc(t) + "</span>";
            else if (m[5]) out += '<span class="mi">' + esc(t) + "</span>";
            else if (m[6]) {
                var cls = "n";
                if (HL_CONST.indexOf(t) >= 0) cls = "kc";
                else if (HL_TYPES.indexOf(t) >= 0) cls = "kt";
                else if (KEYWORDS.indexOf(t) >= 0) cls = "k";
                else if (prev === "namespace") cls = "nn";
                else if (prev === "struct" || prev === "class") cls = "nc";
                out += '<span class="' + cls + '">' + esc(t) + "</span>";
            } else if (m[7]) out += '<span class="o">' + esc(t) + "</span>";
            else if (m[8]) out += '<span class="p">' + esc(t) + "</span>";
            else out += esc(t);
            if (!m[9]) prev = (m[3] && prev === "#include") ? "" : t;
        }
        return out;
    }

    function parsePreset(s) {
        var r = {};
        (s || "").split(",").forEach(function (kv) {
            var p = kv.split("=");
            if (p.length === 2) r[p[0].trim()] = p[1].trim();
        });
        return r;
    }

    /* ---- the decision logic, independent of the DOM ---- */
    function decide(st) {
        var res = { errors: [], warnings: [], macro: null, reason: "", place: "", ref: null };
        var n = st.members.length;
        var names = st.keys === "custom";

        if (st.edit === "no" && st.access === "private") {
            res.errors.push({ text: "No macro can reach private members from outside the class. Write to_json/from_json by hand using the public interface, for example in a specialization of adl_serializer.", link: "third_party", linkText: "How do I convert third-party types?" });
        }
        if (st.dir === "both" && st.ctor === "no") {
            res.errors.push({ text: "Every macro that generates from_json default-constructs the type. Use Only to JSON, or write the conversion by hand.", link: "non_default", linkText: "Non-default-constructible types" });
        }
        if (names && n === 0) {
            res.errors.push({ text: "The WITH_NAMES macros need at least one key and member pair. Without members there is nothing to rename: choose Member names." });
        }
        var limit = names ? 31 : 63;
        if (n > limit) {
            res.errors.push({ text: "The macros support at most " + limit + " members" + (names ? " with custom names" : "") + ". Write to_json/from_json by hand for larger types." });
        }

        /* identifier checks */
        if (!IDENT.test(st.type) || KEYWORDS.indexOf(st.type) >= 0) res.errors.push({ text: "The type name must be a C++ identifier." });
        if (st.base === "yes" && (!IDENT.test(st.baseName) || KEYWORDS.indexOf(st.baseName) >= 0)) res.errors.push({ text: "The base class name must be a C++ identifier." });
        if (st.base === "yes" && st.baseName === st.type) res.errors.push({ text: "The base class needs a different name than the type." });
        var seenName = {}, seenKey = {};
        st.members.forEach(function (mb, i) {
            var label = "Member " + (i + 1);
            if (!IDENT.test(mb.name) || KEYWORDS.indexOf(mb.name) >= 0) res.errors.push({ text: label + ": the name must be a C++ identifier." });
            else if (seenName[mb.name]) res.errors.push({ text: label + ": the name " + mb.name + " is used twice." });
            else if (mb.name === st.type) res.errors.push({ text: label + ": a member cannot have the name of its class." });
            seenName[mb.name] = true;
            if (!MEMBER_TYPE.test(mb.mtype.trim())) res.errors.push({ text: label + ": enter a type such as int, std::string or std::vector<int>." });
            var key = names ? mb.key : mb.name;
            if (seenKey[key]) res.warnings.push(label + ": the JSON key \"" + key + "\" is used twice; the later member overwrites the earlier one in to_json.");
            seenKey[key] = true;
            if (st.base === "yes" && key === "id") res.warnings.push(label + ": the key \"id\" is also written by the example base class; the derived member overwrites it.");
        });

        if (st.edit === "no" && st.access === "private") return res;

        var intrusive = st.access === "private";
        var parts = ["NLOHMANN_DEFINE", st.base === "yes" ? "DERIVED_TYPE" : "TYPE", intrusive ? "INTRUSIVE" : "NON_INTRUSIVE"];
        if (st.dir === "to") parts.push("ONLY_SERIALIZE");
        else if (st.missing === "default") parts.push("WITH_DEFAULT");
        if (names) parts.push("WITH_NAMES");
        res.macro = parts.join("_");
        res.intrusive = intrusive;
        res.ref = names ? "with_names" : (st.base === "yes" ? "derived" : (intrusive ? "intrusive" : "non_intrusive"));

        var why = [];
        if (intrusive) why.push("Private members need the macro inside the class, where its friend functions can access them");
        else if (st.edit === "no") why.push("You cannot edit the class, so the macro goes next to it in its namespace, which works because all members are public");
        else why.push("All members are public, so the macro can stay outside the class, in its namespace");
        if (st.base === "yes") why.push("the conversion of " + (st.baseName || "the base") + " runs first");
        if (st.dir === "to") why.push("only to_json is generated");
        else if (st.missing === "default") why.push("missing keys keep the value of a default-constructed " + st.type);
        else why.push("a missing key throws out_of_range.403");
        if (names) why.push("each member is preceded by its JSON key");
        res.reason = why.join("; ") + ".";
        res.place = intrusive ? "Write the macro inside the class body." : "Write the macro after the class, in the same namespace.";
        if (st.dir === "to" && st.ctor === "no") res.warnings.push("The type is not default constructible: fine for ONLY_SERIALIZE, but j.get<" + st.type + ">() will not compile.");
        return res;
    }

    /* C++ string literal; control characters as three-digit octal escapes, which cannot run into the next character */
    function cppString(s) {
        return '"' + s.replace(/[\\"\u0000-\u001f\u007f]/g, function (c) {
            if (c === "\\" || c === '"') return "\\" + c;
            var o = c.charCodeAt(0).toString(8);
            return "\\" + ("00" + o).slice(-3);
        }) + '"';
    }

    function macroCall(name, head, pairs, indent) {
        var one = name + "(" + head.concat(pairs).join(", ") + ")";
        if (one.length + indent.length <= 88) return indent + one;
        var lines = [indent + name + "(" + head.join(", ") + (pairs.length ? "," : ")")];
        pairs.forEach(function (p, i) {
            lines.push(indent + "    " + p + (i === pairs.length - 1 ? ")" : ","));
        });
        return lines.join("\n");
    }

    function generate(st, res) {
        var ns = "ns";
        var T = st.type, B = st.baseName;
        var priv = res.intrusive;
        var names = st.keys === "custom";
        var suffix = st.dir === "to" ? "_ONLY_SERIALIZE" : (st.missing === "default" ? "_WITH_DEFAULT" : "");
        var noCtor = st.ctor === "no" && st.members.length > 0;
        var L = [];
        L.push("#include <iostream>");
        L.push("#include <nlohmann/json.hpp>");
        L.push("");
        L.push("using nlohmann::json;");
        L.push("");
        L.push("namespace " + ns);
        L.push("{");
        if (st.base === "yes") {
            L.push("// stand-in for your base class: it must be serializable itself");
            if (priv) {
                L.push("class " + B);
                L.push("{");
                L.push("  private:");
                L.push("    int id{};");
                L.push("");
                L.push("  public:");
                L.push("    NLOHMANN_DEFINE_TYPE_INTRUSIVE" + suffix + "(" + B + ", id)");
                L.push("};");
            } else {
                L.push("struct " + B);
                L.push("{");
                L.push("    int id{};");
                L.push("};");
                L.push("NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE" + suffix + "(" + B + ", id)");
            }
            L.push("");
        }
        var kw = priv ? "class " : "struct ";
        var inherit = st.base === "yes" ? (priv ? " : public " + B : " : " + B) : "";
        L.push(kw + T + inherit);
        L.push("{");
        if (priv) L.push("  private:");
        st.members.forEach(function (mb) {
            L.push("    " + mb.mtype.trim() + " " + mb.name + (noCtor ? ";" : "{};"));
        });
        var head = [T];
        if (st.base === "yes") head.push(B);
        var pairs = st.members.map(function (mb) {
            return names ? cppString(mb.key) + ", " + mb.name : mb.name;
        });
        if (noCtor || priv) {
            if (st.members.length) L.push("");
            if (priv) L.push("  public:");
        }
        if (noCtor) {
            var params = st.members.map(function (mb) { return mb.mtype.trim() + " " + mb.name + "_"; }).join(", ");
            var inits = st.members.map(function (mb) { return mb.name + "(" + mb.name + "_)"; }).join(", ");
            L.push("    " + T + "(" + params + ")");
            L.push("        : " + inits);
            L.push("    {}");
            if (priv) L.push("");
        }
        if (priv) {
            L.push(macroCall(res.macro, head, pairs, "    "));
            L.push("};");
        } else {
            L.push("};");
            L.push("");
            L.push(macroCall(res.macro, head, pairs, ""));
        }
        L.push("} // namespace " + ns);
        L.push("");
        L.push("int main()");
        L.push("{");
        var Q = ns + "::" + T;
        if (noCtor) {
            L.push("    " + Q + " p{" + st.members.map(function (mb) { return mb.mtype.trim() + "{}"; }).join(", ") + "};");
        } else {
            L.push("    " + Q + " p{};");
        }
        L.push("    json j = p;  // to_json");
        L.push("    std::cout << j.dump() << '\\n';");
        if (st.dir === "both") {
            L.push("");
            L.push("    auto p2 = j.get<" + Q + ">();  // from_json");
            L.push("    std::cout << (json(p2) == j) << '\\n';  // round trip: 1");
            if (st.missing === "default") {
                L.push("");
                L.push("    // missing keys keep the defaults");
                L.push("    std::cout << json(json::object().get<" + Q + ">()).dump() << '\\n';");
            } else {
                L.push("    // a missing key throws json::out_of_range (403)");
            }
        }
        L.push("}");
        return L.join("\n") + "\n";
    }

    function copyText(text, done) {
        function fallback() {
            var ta = el("textarea", { readonly: "", "aria-hidden": "true" });
            ta.value = text;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            var ok = false;
            try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
            document.body.removeChild(ta);
            done(ok);
        }
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () { done(true); }, fallback);
        } else {
            fallback();
        }
    }

    /* ---- DOM ---- */
    function setup(root) {
        if (root.dataset.njMcReady) return;
        root.dataset.njMcReady = "1";
        var uid = "nj-mc-" + (++counter);
        var variant = root.getAttribute("data-variant") || "full";
        var preset = parsePreset(root.getAttribute("data-preset"));

        var links = {};
        Array.prototype.forEach.call(root.querySelectorAll("a[data-nj-mc]"), function (a) {
            links[a.getAttribute("data-nj-mc")] = a.getAttribute("href");
        });

        var st = { edit: "yes", access: "public", base: "no", dir: "both", missing: "throw", keys: "members", ctor: "yes",
            type: "person", baseName: "entity",
            members: [{ mtype: "std::string", name: "name", key: "name" }, { mtype: "int", name: "age", key: "age" }] };
        QUESTIONS.forEach(function (q) {
            if (preset[q.id] && q.options.some(function (o) { return o[0] === preset[q.id]; })) st[q.id] = preset[q.id];
        });

        var fallback = root.querySelector(".nj-mc-fallback");
        if (fallback) fallback.hidden = true;

        var app = el("div", { "class": "nj-mc-app" });
        var form = el("form", { "class": "nj-mc-form", "aria-label": "Macro chooser options" });
        form.addEventListener("submit", function (e) { e.preventDefault(); });

        var qgrid = el("div", { "class": "nj-mc-questions" });
        var notes = {};
        var groups = {};
        QUESTIONS.forEach(function (q) {
            var fs = el("fieldset", { "class": "nj-mc-q" });
            fs.appendChild(el("legend", null, q.legend));
            var seg = el("div", { "class": "nj-mc-seg" });
            q.options.forEach(function (o) {
                var id = uid + "-" + q.id + "-" + o[0];
                var inp = el("input", { type: "radio", id: id, name: uid + "-" + q.id, value: o[0] });
                if (st[q.id] === o[0]) inp.checked = true;
                inp.addEventListener("change", function () { st[q.id] = o[0]; update(); });
                seg.appendChild(inp);
                seg.appendChild(el("label", { "for": id }, o[1]));
            });
            fs.appendChild(seg);
            var note = el("p", { "class": "nj-mc-qnote", id: uid + "-" + q.id + "-note" });
            note.hidden = true;
            fs.appendChild(note);
            fs.setAttribute("aria-describedby", note.id);
            notes[q.id] = note;
            groups[q.id] = fs;
            qgrid.appendChild(fs);
        });
        form.appendChild(qgrid);

        /* type editor */
        var editor = el("div", { "class": "nj-mc-editor" });
        var names = el("div", { "class": "nj-mc-names" });
        function textField(label, value, onInput, cls) {
            var id = uid + "-f" + (++counter);
            var w = el("div", { "class": "nj-mc-field" + (cls ? " " + cls : "") });
            w.appendChild(el("label", { "for": id }, label));
            var inp = el("input", { type: "text", id: id, spellcheck: "false", autocomplete: "off", autocapitalize: "off" });
            inp.value = value;
            inp.addEventListener("input", function () { onInput(inp.value); update(); });
            w.appendChild(inp);
            return w;
        }
        names.appendChild(textField("Type name", st.type, function (v) { st.type = v.trim(); }));
        var baseField = textField("Base class", st.baseName, function (v) { st.baseName = v.trim(); }, "nj-mc-basefield");
        names.appendChild(baseField);
        editor.appendChild(names);

        var mtable = el("div", { "class": "nj-mc-members", role: "group", "aria-label": "Member variables" });
        var mhead = el("div", { "class": "nj-mc-mrow nj-mc-mhead", "aria-hidden": "true" });
        mhead.appendChild(el("span", null, "Member type"));
        mhead.appendChild(el("span", null, "Member name"));
        var keyHead = el("span", { "class": "nj-mc-keycol" }, "JSON key");
        mhead.appendChild(keyHead);
        mhead.appendChild(el("span"));
        mtable.appendChild(mhead);
        var mbody = el("div", { "class": "nj-mc-mbody" });
        mtable.appendChild(mbody);
        var addBtn = el("button", { type: "button", "class": "nj-mc-add" }, "Add member");
        addBtn.addEventListener("click", function () {
            var k = st.members.length + 1;
            var nm = "member" + k;
            while (st.members.some(function (mb) { return mb.name === nm; })) nm = "member" + (++k);
            st.members.push({ mtype: "int", name: nm, key: nm });
            renderMembers();
            update();
            var rows = mbody.querySelectorAll(".nj-mc-mrow");
            var last = rows[rows.length - 1];
            if (last) last.querySelector("input").focus();
        });
        editor.appendChild(mtable);
        editor.appendChild(addBtn);
        if (variant === "full") form.appendChild(editor);

        function renderMembers() {
            mbody.textContent = "";
            st.members.forEach(function (mb, i) {
                var row = el("div", { "class": "nj-mc-mrow" });
                function cell(prop, label, cls) {
                    var inp = el("input", { type: "text", spellcheck: "false", autocomplete: "off", autocapitalize: "off",
                        "aria-label": label + " of member " + (i + 1), placeholder: label, "class": cls || "" });
                    inp.value = mb[prop];
                    inp.addEventListener("input", function () {
                        var keyFollows = prop === "name" && mb.key === mb.name;
                        mb[prop] = prop === "key" ? inp.value : inp.value.trim();
                        if (keyFollows) {
                            mb.key = mb.name;
                            var k = row.querySelector(".nj-mc-keycol");
                            if (k) k.value = mb.key;
                        }
                        update();
                    });
                    row.appendChild(inp);
                }
                cell("mtype", "Type");
                cell("name", "Name");
                cell("key", "JSON key", "nj-mc-keycol");
                var rm = el("button", { type: "button", "class": "nj-mc-rm", "aria-label": "Remove member " + (i + 1), title: "Remove member" });
                rm.appendChild(el("span", { "aria-hidden": "true" }, "\u00d7"));
                rm.addEventListener("click", function () {
                    st.members.splice(i, 1);
                    renderMembers();
                    update();
                    var btns = mbody.querySelectorAll(".nj-mc-rm");
                    (btns[Math.min(i, btns.length - 1)] || addBtn).focus();
                });
                row.appendChild(rm);
                mbody.appendChild(row);
            });
        }
        renderMembers();
        app.appendChild(form);

        /* output */
        var out = el("div", { "class": "nj-mc-out" });
        var result = el("div", { "class": "nj-mc-result", role: "status", "aria-live": "polite" });
        out.appendChild(result);
        var hints = el("ul", { "class": "nj-mc-hints" });
        out.appendChild(hints);
        var codeWrap = el("div", { "class": "nj-mc-code" });
        var bar = el("div", { "class": "nj-mc-codebar" });
        bar.appendChild(el("span", { "class": "nj-mc-codetitle" }, "Generated code (C++11)"));
        var copyBtn = el("button", { type: "button", "class": "nj-mc-copy", "aria-label": "Copy generated code" }, "Copy");
        var copyStatus = el("span", { "class": "nj-mc-copystatus", role: "status", "aria-live": "polite" });
        bar.appendChild(copyStatus);
        bar.appendChild(copyBtn);
        codeWrap.appendChild(bar);
        var hl = el("div", { "class": "language-cpp highlight" });
        var pre = el("pre");
        var code = el("code", { tabindex: "0", "aria-label": "Generated C++ code" });
        pre.appendChild(code);
        hl.appendChild(pre);
        codeWrap.appendChild(hl);
        if (variant === "full") out.appendChild(codeWrap);
        app.appendChild(out);
        root.appendChild(app);

        var currentCode = "";
        var statusTimer = null;
        copyBtn.addEventListener("click", function () {
            copyText(currentCode, function (ok) {
                copyStatus.textContent = ok ? "Copied" : "Press Ctrl+C / Cmd+C to copy";
                if (!ok) {
                    var r = document.createRange();
                    r.selectNodeContents(code);
                    var s = window.getSelection();
                    s.removeAllRanges();
                    s.addRange(r);
                }
                clearTimeout(statusTimer);
                statusTimer = setTimeout(function () { copyStatus.textContent = ""; }, 2500);
            });
        });

        function setNote(id, text) {
            notes[id].hidden = !text;
            notes[id].textContent = text || "";
        }

        function addLink(parent, key, text) {
            if (!key || !links[key]) return;
            parent.appendChild(document.createTextNode(" "));
            parent.appendChild(el("a", { href: links[key] }, text));
        }

        function update() {
            var dirTo = st.dir === "to";
            groups.missing.disabled = dirTo;
            groups.missing.classList.toggle("nj-mc-off", dirTo);
            setNote("missing", dirTo ? "Not applicable: ONLY_SERIALIZE generates no from_json." : "");
            setNote("access", st.edit === "no" && st.access === "private" ? "Private members of a class you cannot edit are out of reach for every macro." : "");
            setNote("ctor", st.ctor === "no" && !dirTo ? "Parsing needs a default constructor; only Only to JSON works." : "");
            baseField.hidden = st.base !== "yes";
            mtable.classList.toggle("nj-mc-custom", st.keys === "custom");
            keyHead.hidden = st.keys !== "custom";

            var res = decide(st);
            result.textContent = "";
            hints.textContent = "";
            if (res.macro && !res.errors.length) {
                result.className = "nj-mc-result";
                result.appendChild(el("p", { "class": "nj-mc-label" }, "Recommended macro"));
                var name = el("p", { "class": "nj-mc-macro" });
                name.appendChild(el("code", null, res.macro));
                result.appendChild(name);
                var why = el("p", { "class": "nj-mc-why" }, res.reason + " " + res.place);
                addLink(why, res.ref, "Reference");
                result.appendChild(why);
            } else {
                result.className = "nj-mc-result nj-mc-bad";
                result.appendChild(el("p", { "class": "nj-mc-label" }, res.macro ? "Cannot generate this macro yet" : "No macro fits"));
                res.errors.forEach(function (e) {
                    var p = el("p", { "class": "nj-mc-why" }, e.text);
                    addLink(p, e.link, e.linkText);
                    result.appendChild(p);
                });
            }
            res.warnings.forEach(function (w) { hints.appendChild(el("li", null, w)); });
            hints.hidden = !res.warnings.length;

            var ok = res.macro && !res.errors.length;
            codeWrap.hidden = !ok;
            if (ok) {
                currentCode = generate(st, res);
                code.innerHTML = highlight(currentCode);
            }
            root.setAttribute("data-nj-mc-macro", ok ? res.macro : "");
        }
        update();
    }

    function init() {
        Array.prototype.forEach.call(document.querySelectorAll(".nj-macro-chooser"), setup);
    }

    if (typeof document$ !== "undefined" && document$ && typeof document$.subscribe === "function") {
        document$.subscribe(init);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    /* exported for the verification scripts */
    window.njMacroChooser = { decide: decide, generate: generate };
})();
