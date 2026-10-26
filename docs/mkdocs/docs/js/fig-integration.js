/* figures: integration
 *
 * Namespace name builder on features/namespace.md. The page ships a static strip for version 3.11.2 with
 * JSON_DIAGNOSTICS=1; this script adds a version selector and one checkbox per ABI-affecting macro and rebuilds the
 * strip. Tags, their order, and the versions that know them follow include/nlohmann/detail/abi_macros.hpp and the
 * "Version history" section of the page; a tag that a version does not have cannot be ticked.
 */
(function () {
    "use strict";

    var VERSIONS = ["3.11.2", "3.11.3", "3.12.0", "3.13.0"];
    // macro, tag, first version with the tag, true if any definition counts (#ifdef) instead of a non-zero value
    var TAGS = [
        ["JSON_DIAGNOSTICS", "_diag", "3.11.2"],
        ["JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON", "_ldvcmp", "3.11.2"],
        ["JSON_DIAGNOSTIC_POSITIONS", "_dp", "3.12.0"],
        ["JSON_BRACE_INIT_COPY_SEMANTICS", "_bics", "3.13.0"],
        ["JSON_PRECISE_STREAM_POSITION", "_psp", "3.13.0"],
        ["JSON_STRICT_NUL_HANDLING", "_snul", "3.13.0"],
        ["JSON_STRICT_BINARY_UTF8", "_sbu8", "3.13.0"],
        ["JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS", "_ekmo", "3.13.0"],
        ["JSON_DISABLE_STREAM_BULK_SCAN", "_dsbs", "3.13.0"],
        ["JSON_DISABLE_UNLOCKED_FILE_IO", "_dufio", "3.13.0"],
        ["JSON_NO_SIMD", "_ns", "3.13.0", true],
        ["JSON_VIEW_NO_SIMD", "_vns", "3.13.0", true],
        ["JSON_VIEW_USE_SSSE3", "_vssse3", "3.13.0", true]
    ];
    var NO_VERSION = "NLOHMANN_JSON_NAMESPACE_NO_VERSION";

    function el(tag, cls, text) {
        var node = document.createElement(tag);
        if (cls) { node.className = cls; }
        if (text !== undefined) { node.textContent = text; }
        return node;
    }

    function seg(kind, code, note) {
        var span = el("span", "nj-integration-ns__seg nj-integration-ns__seg--" + kind);
        span.appendChild(el("code", "", code));
        var small = el("small");
        // allow line breaks after underscores so that long macro names stay narrow
        (note || "\u00a0").split("_").forEach(function (part, i, all) {
            small.appendChild(document.createTextNode(part + (i < all.length - 1 ? "_" : "")));
            if (i < all.length - 1) { small.appendChild(el("wbr")); }
        });
        span.appendChild(small);
        return span;
    }

    function setup(fig) {
        if (fig.getAttribute("data-nj-ready")) { return; }
        fig.setAttribute("data-nj-ready", "1");
        var strip = fig.querySelector(".nj-integration-ns__strip");
        var caption = fig.querySelector("figcaption");
        var uid = "nj-integration-ns-" + Math.random().toString(36).slice(2, 8);
        var form = el("form", "nj-integration-ns__controls");
        form.setAttribute("aria-label", "Namespace name builder");
        form.addEventListener("submit", function (e) { e.preventDefault(); });

        var vlabel = el("label", "nj-integration-ns__version", "Library version ");
        var select = el("select");
        VERSIONS.forEach(function (v) {
            var option = el("option", "", v);
            option.value = v;
            option.selected = v === "3.11.2";
            select.appendChild(option);
        });
        vlabel.appendChild(select);
        form.appendChild(vlabel);

        var list = el("fieldset", "nj-integration-ns__list");
        list.appendChild(el("legend", "", "ABI-affecting macros, in tag order"));
        var boxes = TAGS.concat([[NO_VERSION, "", "3.11.2"]]).map(function (t, i) {
            var label = el("label", "nj-integration-ns__opt");
            var box = el("input");
            box.type = "checkbox";
            box.id = uid + "-" + i;
            box.checked = t[0] === "JSON_DIAGNOSTICS";
            label.htmlFor = box.id;
            label.appendChild(box);
            label.appendChild(el("code", "", t[0] + (t[3] ? "" : "=1")));
            var meta = el("span", "nj-integration-ns__meta");
            meta.appendChild(el("span", "nj-integration-ns__hint",
                t[0] === NO_VERSION ? "drops the version" : (t[3] ? "defined: " : "") + t[1]));
            meta.appendChild(el("span", "nj-integration-ns__since", "since " + t[2]));
            label.appendChild(meta);
            list.appendChild(label);
            return { def: t, box: box, label: label };
        });
        form.appendChild(list);
        fig.insertBefore(form, caption);

        function update() {
            var version = select.value, index = VERSIONS.indexOf(version);
            var parts = [seg("root", "nlohmann", "root namespace"), seg("sep", "::"), seg("abi", "json_abi", "always")];
            var noVersion = false, defs = [];
            boxes.forEach(function (b) {
                var available = VERSIONS.indexOf(b.def[2]) <= index;
                b.box.disabled = !available;
                if (!available) { b.box.checked = false; }
                b.label.classList.toggle("is-unavailable", !available);
                if (!b.box.checked) { return; }
                defs.push(b.def[0] + (b.def[3] ? "" : "=1"));
                if (b.def[0] === NO_VERSION) { noVersion = true; } else { parts.push(seg("tag", b.def[1], b.def[0] + (b.def[3] ? "" : "=1"))); }
            });
            if (!noVersion) { parts.push(seg("ver", "_v" + version.replace(/\./g, "_"), "version " + version)); }
            strip.textContent = "";
            parts.forEach(function (p) { strip.appendChild(p); });
            strip.setAttribute("aria-label", "Resulting namespace: nlohmann::" + parts.slice(2).map(function (p) {
                return p.firstChild.textContent;
            }).join(""));
            caption.textContent = "Version " + version + (defs.length === 0 ? " with no ABI-affecting macro defined" :
                defs.length > 3 ? " with " + defs.length + " of the macros defined" : " with " + defs.join(", ")) + ".";
        }
        form.addEventListener("change", update);
        update();
    }

    function init() {
        Array.prototype.forEach.call(document.querySelectorAll("[data-nj-integration-ns]"), setup);
    }

    if (typeof document$ !== "undefined" && document$ && typeof document$.subscribe === "function") {
        document$.subscribe(init);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
