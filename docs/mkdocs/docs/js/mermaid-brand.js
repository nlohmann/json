/*
 * Brand look for Mermaid diagrams.
 *
 * Material for MkDocs loads Mermaid on demand and calls mermaid.initialize() with its own theme CSS. This script
 * catches Mermaid when it arrives on window.mermaid and wraps two calls:
 *   - initialize(): adds the brand's font, spacing and shape rules below to Material's options;
 *   - render(): marks hexagons ({{...}} in a flowchart) with the class "nj-decision", since in the SVG a hexagon and
 *     a parallelogram are both a <polygon> that CSS cannot tell apart; and keeps a wide diagram at 80 % of its size
 *     or more, so its text stays readable and the diagram scrolls sideways instead (see .mermaid in brand.css).
 * The colours come from the --md-mermaid-* variables in brand.css, so the diagrams follow the light/dark toggle.
 */
(function () {
    "use strict";

    var css = [
        // text: Inter everywhere, labels on boxes semibold
        ".label, .nodeLabel, .nodeLabel p, .edgeLabel, .edgeLabel p, .cluster span, text { font-family: var(--md-mermaid-font-family) !important; }",
        ".nodeLabel, .nodeLabel p { font-weight: 600; }",
        ".edgeLabel, .edgeLabel p { color: var(--md-default-fg-color--light) !important; font-size: 13px; font-weight: 500; }",

        // boxes: 1.5 px outline, 6 px corners; "(...)" nodes stay rounder than "[...]" nodes
        ".node rect, .node path, .node polygon, .node circle, .node ellipse { stroke-width: 1.5px !important; }",
        ".node rect:not([rx]) { rx: 6px; ry: 6px; }",
        ".node rect[rx] { rx: 14px; ry: 14px; }",

        // decisions: solid blue hexagons with white text
        ".node.nj-decision polygon { fill: var(--nj-band) !important; stroke: var(--nj-band) !important; stroke-linejoin: round; }",
        ".node.nj-decision .nodeLabel, .node.nj-decision .nodeLabel p { color: #fff !important; }",

        // lines: 1.5 px, solid unless written as -.-
        ".edgePath .path, .flowchart-link { stroke-width: 1.5px !important; }",
        "marker path { stroke: none !important; }",

        // class diagrams; a node with its own fill ("style X fill:#CCCCFF" on the exception pages) is the highlighted
        // one and gets soft blue, which also works in dark mode
        "g.classGroup rect, .classGroup line, g.node.default > g > path { stroke-width: 1.5px !important; }",
        ".node path[style*='fill'], .node rect[style*='fill'] { fill: var(--nj-blue-soft) !important; }",
        ".relation { stroke-width: 1.5px !important; }",

        // sequence diagrams
        ".actor { stroke-width: 1.5px !important; rx: 6px; ry: 6px; }",
        ".actor-line { stroke-width: 1px; }",
        ".messageLine0, .messageLine1 { stroke-width: 1.5px !important; }",
        ".note { rx: 6px; ry: 6px; }"
    ].join("\n");

    var options = {
        theme: "base",
        fontFamily: "Inter, sans-serif",
        themeVariables: { fontFamily: "Inter, sans-serif", fontSize: "15px" },
        flowchart: { curve: "basis", padding: 12, nodeSpacing: 36, rankSpacing: 48, wrappingWidth: 240 }
    };

    var minScale = 0.8;

    function postProcess(svg) {
        // shrink to fit the column, but not below minScale
        svg = svg.replace(/^(<svg[^>]*style="[^"]*)max-width:\s*([\d.]+)px;/, function (all, head, width) {
            return head + "max-width: " + width + "px; min-width: " + Math.round(width * minScale) + "px;";
        });
        // add class "nj-decision" to every flowchart node drawn as a hexagon (a polygon with six corners)
        return svg.replace(/<g class="node ([^"]*)"([^>]*)><polygon points="([^"]*)"/g, function (all, cls, rest, points) {
            var corners = points.trim().split(/\s+/).length;
            return corners === 6 ? '<g class="node nj-decision ' + cls + '"' + rest + '><polygon points="' + points + '"' : all;
        });
    }

    function brand(mermaid) {
        if (!mermaid || typeof mermaid.initialize !== "function" || mermaid.njBrand) {
            return mermaid;
        }
        var initialize = mermaid.initialize.bind(mermaid);
        var render = mermaid.render.bind(mermaid);
        mermaid.initialize = function (config) {
            config = Object.assign({}, config || {});
            config.theme = options.theme;
            config.fontFamily = options.fontFamily;
            config.themeVariables = Object.assign({}, config.themeVariables, options.themeVariables);
            config.flowchart = Object.assign({}, config.flowchart, options.flowchart);
            config.themeCSS = (config.themeCSS || "") + "\n" + css;
            return initialize(config);
        };
        mermaid.render = function () {
            return render.apply(null, arguments).then(function (result) {
                result.svg = postProcess(result.svg);
                return result;
            });
        };
        mermaid.njBrand = true;
        return mermaid;
    }

    // Mermaid ends with globalThis["mermaid"] = ..., which runs the setter below
    var current = brand(window.mermaid);
    Object.defineProperty(window, "mermaid", {
        configurable: true,
        get: function () { return current; },
        set: function (value) { current = brand(value); }
    });
})();
