/* figures: jsonview -- stepper for the edit frames on features/json_view.md.
   Without JS the frames (.nj-jsonview-step) show one below the other; with JS one frame at a time, with
   previous/next and one button per step. Never advances on its own. */
(function () {
    "use strict";

    function njJsonviewInit(root) {
        if (root.classList.contains("is-enhanced")) return;
        var steps = Array.prototype.slice.call(root.querySelectorAll(".nj-jsonview-step"));
        if (steps.length < 2) return;
        var current = 0;

        var bar = document.createElement("div");
        bar.className = "nj-jsonview-controls";
        bar.setAttribute("role", "group");
        bar.setAttribute("aria-label", "Edit steps");

        function button(label, aria, onClick) {
            var b = document.createElement("button");
            b.type = "button";
            b.textContent = label;
            b.setAttribute("aria-label", aria);
            b.addEventListener("click", onClick);
            bar.appendChild(b);
            return b;
        }

        var prev = button("‹ Back", "Previous step", function () { show(current - 1, true); });
        var dots = steps.map(function (s, i) {
            return button(String(i + 1), "Step " + (i + 1) + ": " + (s.getAttribute("data-label") || ""), function () { show(i, true); });
        });
        var next = button("Next ›", "Next step", function () { show(current + 1, true); });
        var status = document.createElement("span");
        status.className = "nj-jsonview-status";
        status.setAttribute("aria-live", "polite");
        bar.appendChild(status);

        function show(i, focusKeep) {
            current = Math.max(0, Math.min(steps.length - 1, i));
            steps.forEach(function (s, k) {
                s.classList.toggle("is-current", k === current);
                s.setAttribute("aria-hidden", k === current ? "false" : "true");
            });
            dots.forEach(function (d, k) {
                if (k === current) d.setAttribute("aria-current", "step"); else d.removeAttribute("aria-current");
            });
            prev.disabled = current === 0;
            next.disabled = current === steps.length - 1;
            status.textContent = "Step " + (current + 1) + " of " + steps.length;
            if (focusKeep && document.activeElement && document.activeElement.disabled) {
                (current === 0 ? next : prev).focus();
            }
        }

        root.addEventListener("keydown", function (e) {
            if (e.target.tagName !== "BUTTON") return;
            if (e.key === "ArrowRight") { show(current + 1, true); e.preventDefault(); }
            else if (e.key === "ArrowLeft") { show(current - 1, true); e.preventDefault(); }
        });

        root.insertBefore(bar, root.firstChild);
        root.classList.add("is-enhanced");
        show(0, false);
    }

    function njJsonviewAll() {
        var roots = document.querySelectorAll("[data-nj-jsonview-steps]");
        for (var i = 0; i < roots.length; i++) njJsonviewInit(roots[i]);
    }

    if (typeof document$ !== "undefined" && document$ && typeof document$.subscribe === "function") {
        document$.subscribe(njJsonviewAll);
    } else if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", njJsonviewAll);
    } else {
        njJsonviewAll();
    }
})();
