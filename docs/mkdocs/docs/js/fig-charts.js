/* figures: charts. Number literal explorer on features/types/number_handling.md.
   The table in .nj-charts-num is the source and the no-JS fallback; its rows were verified by compiling a program
   against include/ (json::parse + type() + dump()). The explorer only looks literals up in that table: it does not
   parse numbers itself, so anything else is reported as "not in the verified list". */
(function () {
    "use strict";

    var WHY = {
        "0": "No fraction, exponent, or minus sign: stored as unsigned integer.",
        "-0": "Leading minus sign: stored as signed integer; the serialization does not reproduce the -.",
        "-0.0": "Has a fraction: stored as double, which keeps the sign of zero.",
        "1E3": "Has an exponent: always stored as double.",
        "-12345678912345789123456789": "Smaller than INT64_MIN: does not fit std::int64_t, so it is stored as double.",
        "18446744073709551615": "2^64-1 is the largest value std::uint64_t can store without loss.",
        "18446744073709551616": "2^64 does not fit std::uint64_t, so it is stored as double.",
        "-9223372036854775808": "-2^63 is the smallest value std::int64_t can store.",
        "1E400": "Its rounded value is not finite as double: parsing throws out_of_range.406.",
        "1E-400": "Too small for double: becomes zero, with the sign of the number.",
        "3.141592653589793238462643383279": "Rounded to the nearest double, then printed with the fewest digits that read back.",
        "2555.5599999999999": "The fewest digits that read back as the same double are 2555.56.",
        "0.0000972439793401814": "The %g layout switches to scientific notation.",
        "12345E-5": "The %g layout prints this double without exponent."
    };

    function init() {
        var roots = document.querySelectorAll(".nj-charts-num");
        Array.prototype.forEach.call(roots, setup);
    }

    function setup(root, idx) {
        if (root.dataset.njChartsReady) return;
        var table = root.querySelector("table");
        if (!table) return;
        root.dataset.njChartsReady = "1";

        var entries = [];
        Array.prototype.forEach.call(table.querySelectorAll("tbody tr"), function (tr) {
            var c = tr.querySelectorAll("td");
            if (c.length < 3) return;
            entries.push({ lit: c[0].textContent.trim(), type: c[1].textContent.trim(), dump: c[2].textContent.trim(), row: tr });
        });
        if (!entries.length) return;

        var id = "nj-charts-num-" + idx;
        var ui = document.createElement("div");
        ui.className = "nj-charts-num-ui";
        ui.innerHTML =
            '<ul class="nj-charts-num-chips" aria-label="Literals to show"></ul>' +
            '<div id="' + id + '-out" aria-live="polite"></div>';
        root.insertBefore(ui, root.firstChild);

        var list = ui.querySelector("ul");
        var out = ui.querySelector("#" + id + "-out");
        var buttons = [];

        entries.forEach(function (e) {
            var li = document.createElement("li");
            var b = document.createElement("button");
            b.type = "button";
            b.className = "nj-charts-num-chip";
            b.textContent = e.lit;
            b.setAttribute("aria-pressed", "false");
            b.setAttribute("aria-label", "Show literal " + e.lit);
            b.addEventListener("click", function () { show(e.lit); });
            li.appendChild(b);
            list.appendChild(li);
            buttons.push(b);
        });

        function show(text) {
            var lit = text.trim();
            var hit = null;
            entries.forEach(function (e, i) {
                var on = e.lit === lit;
                if (on) hit = e;
                buttons[i].setAttribute("aria-pressed", on ? "true" : "false");
                e.row.classList.toggle("nj-charts-num-hit", on);
            });
            out.textContent = "";
            if (hit) {
                var dl = document.createElement("dl");
                dl.className = "nj-charts-num-out";
                [["literal", hit.lit, true], ["stored as", hit.type, false], ["dump()", hit.dump, true],
                 ["why", WHY[hit.lit] || "", false]].forEach(function (p) {
                    if (!p[1]) return;
                    var dt = document.createElement("dt"); dt.textContent = p[0];
                    var dd = document.createElement("dd");
                    if (p[2] && p[1].indexOf("(") !== 0) { var c = document.createElement("code"); c.textContent = p[1]; dd.appendChild(c); }
                    else dd.textContent = p[1];
                    dl.appendChild(dt); dl.appendChild(dd);
                });
                out.appendChild(dl);
            }
        }

        show(entries[1] ? entries[1].lit : entries[0].lit);
    }

    if (typeof document$ !== "undefined" && document$ && typeof document$.subscribe === "function") {
        document$.subscribe(init);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
