/*
 * Marks links that leave the site with the class "nj-external", which brand.css turns into a small icon in front of
 * the link. A link is external when its host is neither the current one nor the production site. Links in the page
 * actions (edit, raw), buttons, header anchors, and links that only wrap an image (badges) are left alone.
 * Runs through Material's document$ (navigation.instant), so it also applies after an instant page switch.
 */
(function () {
    "use strict";

    function mark() {
        var links = document.querySelectorAll(".md-typeset a[href]");
        for (var i = 0; i < links.length; i++) {
            var a = links[i];
            if (a.hostname === "" || a.hostname === location.hostname || a.hostname === "json.nlohmann.me") {
                continue;
            }
            if (a.protocol !== "http:" && a.protocol !== "https:") {
                continue;
            }
            if (a.matches(".md-button, .md-content__button, .headerlink") || a.querySelector("img, svg")) {
                continue;
            }
            a.classList.add("nj-external");
        }
    }

    if (window.document$ && window.document$.subscribe) {
        window.document$.subscribe(mark);
    } else {
        document.addEventListener("DOMContentLoaded", mark);
    }
})();
