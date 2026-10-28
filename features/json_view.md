# Zero-copy JSON views

`#!cpp <nlohmann/json_view.hpp>` adds a read-only, non-owning way to look at a parsed JSON text, as an alternative to
building a [`basic_json`](../api/basic_json/index.md) tree with [`parse()`](../api/basic_json/parse.md).

## The problem

[`basic_json::parse()`](../api/basic_json/parse.md) builds a tree of `basic_json` values: one allocation for every
array and object, and every string copied into its own `std::string`. That is the right trade-off when the program
goes on to read and write the value freely, but it does more work than necessary when only a small part of a large
JSON text is actually needed, or when the same text is parsed over and over (many small messages, for instance) and
most of the resulting tree is thrown away almost immediately.

## The idea

[`basic_json_document::parse()`](../api/basic_json_document/parse.md) parses the same JSON grammar, with the same
options, but instead of a tree it builds a flat index of the values it found: one
[16-byte entry](../home/architecture.md#node-index-of-json-views) per value (and one per object key), in document
order. Integers are converted while parsing and stored in their entry. Floating-point numbers and strings are
referenced in place in the source text: a float is converted when it is read, and only strings that contain escape
sequences are decoded, into one shared buffer owned by the document.

[`basic_json_view`](../api/basic_json_view/index.md) is a small, trivially copyable handle (two pointers) into that
index. It gives you the read-only, type-inspection part of the `basic_json` interface —
[`type()`](../api/basic_json_view/type.md) and the `is_*()` predicates,
[`size()`](../api/basic_json_view/size.md)/[`empty()`](../api/basic_json_view/empty.md) — as well as element access
([`operator[]`](../api/basic_json_view/operator%5B%5D.md), [`at`](../api/basic_json_view/at.md),
[`front`](../api/basic_json_view/front.md)/[`back`](../api/basic_json_view/back.md)), lookup
([`find`](../api/basic_json_view/find.md), [`contains`](../api/basic_json_view/contains.md),
[`count`](../api/basic_json_view/count.md)), and iteration
([`begin`](../api/basic_json_view/begin.md)/[`end`](../api/basic_json_view/end.md),
[`items`](../api/basic_json_view/items.md)) — without ever allocating a `basic_json` value. When you do need an
actual `basic_json` value for a subtree, [`materialize()`](../api/basic_json_view/materialize.md) builds exactly the
one [`parse()`](../api/basic_json/parse.md) would have produced for it.

The same small text, parsed both ways:

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-jsonview " viewBox="0 0 840 692" role="img" aria-labelledby="fig-jvl-title fig-jvl-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jvl-title">The same J&#8203;SON text parsed by basic_json::parse() and by json_document::parse()</title>
<desc id="fig-jvl-title-d">The text {&quot;port&quot;: 6379, &quot;price&quot;: 19.90, &quot;tags&quot;: [&quot;eu&quot;, &quot;a\&quot;b&quot;]}. Top: basic_json::parse() builds a tree: the root json value points to a std::map whose three nodes are separate heap allocations; the price is stored as the double 19.9; the tags array is a std::vector of two json values, each pointing to its own std::string. Bottom: json_document::parse() keeps the 54 bytes of source text and builds a flat index of nine 16-byte nodes in document order: object, key port, unsigned integer 6379 (the converted value is in the node), key price, float, key tags, array, string eu, and an escaped string. Keys, the float, and the plain string point back into the source text; the escaped string points into the document&#x27;s buffer of decoded strings. A json_view is two pointers: one to the document and one to a node, here the array.</desc>
<defs>
<marker id="jvl-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-str" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-str nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-key" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-key nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-num" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-num nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-dec" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-dec nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvl-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-h" x="16" y="26" xml:space="preserve">basic_json::parse(): a tree, every array, object, and string in its own heap allocation</text>
<rect class="nj-jsonview-box" x="16" y="98" width="60" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="46" y="120" text-anchor="middle" xml:space="preserve">json</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M76 115 L106 115" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="108" y="98" width="84" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="150" y="120" text-anchor="middle" xml:space="preserve">std::map</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 C192 115 226 67 226 67" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="228" y="50" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="72" xml:space="preserve">&quot;port&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-num" x="396" y="72" text-anchor="end" xml:space="preserve">6379</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 C192 115 226 115 226 115" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="228" y="98" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="120" xml:space="preserve">&quot;price&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-num" x="396" y="120" text-anchor="end" xml:space="preserve">19.9</text>
<text class="nj-jsonview-note" x="418" y="120" xml:space="preserve">double: 19.90 is gone</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 C192 115 226 163 226 163" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="228" y="146" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="168" xml:space="preserve">&quot;tags&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-line" x="396" y="168" text-anchor="end" xml:space="preserve">•</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M408 163 L442 163" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="444" y="146" width="104" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="496" y="168" text-anchor="middle" xml:space="preserve">std::vector</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M548 163 L576 163" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="578" y="146" width="92" height="34" rx="5"/>
<path class="nj-jsonview-sep" d="M624 146 V180"/>
<text class="nj-jsonview-mono" x="601" y="168" text-anchor="middle" xml:space="preserve">json</text>
<text class="nj-jsonview-mono" x="647" y="168" text-anchor="middle" xml:space="preserve">json</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M601 146 C601 126 706 150 706 130" marker-end="url(#jvl-line)"/>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M647 180 C647 200 706 176 706 196" marker-end="url(#jvl-line)"/>
<rect class="nj-jsonview-heap" x="708" y="113" width="126" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-sm nj-jsonview-c-str" x="771" y="135" text-anchor="middle" xml:space="preserve">std::string eu</text>
<rect class="nj-jsonview-heap" x="708" y="179" width="126" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-sm nj-jsonview-c-str" x="771" y="201" text-anchor="middle" xml:space="preserve">std::string a&quot;b</text>
<rect class="nj-jsonview-heap" x="16" y="186" width="18" height="14" rx="3"/>
<text class="nj-jsonview-note" x="42" y="198" xml:space="preserve">a separate heap allocation</text>
<path class="nj-jsonview-sep" d="M16 234 H824"/>
<text class="nj-jsonview-h" x="16" y="262" xml:space="preserve">json_document::parse(): the source text stays where it is; one flat index of 16-byte nodes</text>
<text class="nj-jsonview-note" x="16" y="290" xml:space="preserve">source text, 54 bytes (borrowed, or owned by the document)</text>
<rect class="nj-jsonview-ribbon" x="42" y="300" width="756" height="26" rx="4"/>
<rect class="nj-jsonview-span nj-jsonview-c-key" x="71" y="302" width="54" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-num" x="169" y="302" width="54" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-key" x="267" y="302" width="68" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-num" x="379" y="302" width="68" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-key" x="491" y="302" width="54" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-str" x="617" y="302" width="26" height="22" rx="3"/>
<rect class="nj-jsonview-span nj-jsonview-c-dec" x="701" y="302" width="54" height="22" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-byte" x="49" y="317.5" text-anchor="middle" xml:space="preserve">{</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="63" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="77" y="317.5" text-anchor="middle" xml:space="preserve">p</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="91" y="317.5" text-anchor="middle" xml:space="preserve">o</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="105" y="317.5" text-anchor="middle" xml:space="preserve">r</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="119" y="317.5" text-anchor="middle" xml:space="preserve">t</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="133" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="147" y="317.5" text-anchor="middle" xml:space="preserve">:</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="175" y="317.5" text-anchor="middle" xml:space="preserve">6</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="189" y="317.5" text-anchor="middle" xml:space="preserve">3</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="203" y="317.5" text-anchor="middle" xml:space="preserve">7</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="217" y="317.5" text-anchor="middle" xml:space="preserve">9</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="231" y="317.5" text-anchor="middle" xml:space="preserve">,</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="259" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="273" y="317.5" text-anchor="middle" xml:space="preserve">p</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="287" y="317.5" text-anchor="middle" xml:space="preserve">r</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="301" y="317.5" text-anchor="middle" xml:space="preserve">i</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="315" y="317.5" text-anchor="middle" xml:space="preserve">c</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="329" y="317.5" text-anchor="middle" xml:space="preserve">e</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="343" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="357" y="317.5" text-anchor="middle" xml:space="preserve">:</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="385" y="317.5" text-anchor="middle" xml:space="preserve">1</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="399" y="317.5" text-anchor="middle" xml:space="preserve">9</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="413" y="317.5" text-anchor="middle" xml:space="preserve">.</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="427" y="317.5" text-anchor="middle" xml:space="preserve">9</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="441" y="317.5" text-anchor="middle" xml:space="preserve">0</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="455" y="317.5" text-anchor="middle" xml:space="preserve">,</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="483" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="497" y="317.5" text-anchor="middle" xml:space="preserve">t</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="511" y="317.5" text-anchor="middle" xml:space="preserve">a</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="525" y="317.5" text-anchor="middle" xml:space="preserve">g</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="539" y="317.5" text-anchor="middle" xml:space="preserve">s</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="553" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="567" y="317.5" text-anchor="middle" xml:space="preserve">:</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="595" y="317.5" text-anchor="middle" xml:space="preserve">[</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="609" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="623" y="317.5" text-anchor="middle" xml:space="preserve">e</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="637" y="317.5" text-anchor="middle" xml:space="preserve">u</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="651" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="665" y="317.5" text-anchor="middle" xml:space="preserve">,</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="693" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="707" y="317.5" text-anchor="middle" xml:space="preserve">a</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="721" y="317.5" text-anchor="middle" xml:space="preserve">\</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="735" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="749" y="317.5" text-anchor="middle" xml:space="preserve">b</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="763" y="317.5" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="777" y="317.5" text-anchor="middle" xml:space="preserve">]</text>
<text class="nj-jsonview-mono nj-jsonview-byte" x="791" y="317.5" text-anchor="middle" xml:space="preserve">}</text>
<text class="nj-jsonview-tiny" x="49" y="340" text-anchor="middle" xml:space="preserve">0</text>
<text class="nj-jsonview-tiny" x="189" y="340" text-anchor="middle" xml:space="preserve">10</text>
<text class="nj-jsonview-tiny" x="329" y="340" text-anchor="middle" xml:space="preserve">20</text>
<text class="nj-jsonview-tiny" x="469" y="340" text-anchor="middle" xml:space="preserve">30</text>
<text class="nj-jsonview-tiny" x="609" y="340" text-anchor="middle" xml:space="preserve">40</text>
<text class="nj-jsonview-tiny" x="749" y="340" text-anchor="middle" xml:space="preserve">50</text>
<rect class="nj-jsonview-frame" x="16" y="366" width="808" height="254" rx="10"/>
<text class="nj-jsonview-note nj-jsonview-strong" x="30" y="602" xml:space="preserve">json_document: owns the node index and the buffer of decoded strings</text>
<text class="nj-jsonview-note" x="30" y="500" xml:space="preserve">node index: 9 nodes × 16 bytes = 144 bytes, in document order</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="420" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-c-struct" x="78" y="434" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="78" y="451" text-anchor="middle" xml:space="preserve">len 3</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="78" y="465" text-anchor="middle" xml:space="preserve">next 9</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="420" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-c-key" x="166" y="434" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="166" y="451" text-anchor="middle" xml:space="preserve">off 2</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="166" y="465" text-anchor="middle" xml:space="preserve">len 4</text>
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M166 406 C166 367 98 367 98 328" marker-end="url(#jvl-key)"/>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="212" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="420" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-c-num" x="254" y="434" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="254" y="451" text-anchor="middle" xml:space="preserve">6379</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="254" y="465" text-anchor="middle" xml:space="preserve">(converted)</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="420" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-c-key" x="342" y="434" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="342" y="451" text-anchor="middle" xml:space="preserve">off 16</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="342" y="465" text-anchor="middle" xml:space="preserve">len 5</text>
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M342 406 C342 367 301 367 301 328" marker-end="url(#jvl-key)"/>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="420" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-c-num" x="430" y="434" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="430" y="451" text-anchor="middle" xml:space="preserve">off 24</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="430" y="465" text-anchor="middle" xml:space="preserve">len 5</text>
<path class="nj-jsonview-arr nj-jsonview-c-num" d="M430 406 C430 367 413 367 413 328" marker-end="url(#jvl-num)"/>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="420" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-c-key" x="518" y="434" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="518" y="451" text-anchor="middle" xml:space="preserve">off 32</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="518" y="465" text-anchor="middle" xml:space="preserve">len 4</text>
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M518 406 C518 367 518 367 518 328" marker-end="url(#jvl-key)"/>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="420" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-c-struct" x="606" y="434" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="606" y="451" text-anchor="middle" xml:space="preserve">len 2</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="606" y="465" text-anchor="middle" xml:space="preserve">next 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="652" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="420" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-c-str" x="694" y="434" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="694" y="451" text-anchor="middle" xml:space="preserve">off 41</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="694" y="465" text-anchor="middle" xml:space="preserve">len 2</text>
<path class="nj-jsonview-arr nj-jsonview-c-str" d="M694 406 C694 367 630 367 630 328" marker-end="url(#jvl-str)"/>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="420" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-c-dec" x="782" y="434" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="782" y="451" text-anchor="middle" xml:space="preserve">escaped</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="782" y="465" text-anchor="middle" xml:space="preserve">len 3</text>
<text class="nj-jsonview-note" x="773" y="568" text-anchor="middle" xml:space="preserve">decoded strings</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="518" width="66" height="30" rx="4"/>
<text class="nj-jsonview-mono" x="751" y="538" text-anchor="middle" xml:space="preserve">a</text>
<text class="nj-jsonview-mono" x="773" y="538" text-anchor="middle" xml:space="preserve">&quot;</text>
<text class="nj-jsonview-mono" x="795" y="538" text-anchor="middle" xml:space="preserve">b</text>
<path class="nj-jsonview-arr nj-jsonview-c-dec" d="M782 474 C782 496 773 496 773 518" marker-end="url(#jvl-dec)"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="470" y="670" text-anchor="end" xml:space="preserve">json_view v = doc.root()[&quot;tags&quot;]</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="480" y="648" width="140" height="34" rx="6"/>
<path class="nj-jsonview-sep" d="M550 648 V682"/>
<text class="nj-jsonview-mono" x="515" y="670" text-anchor="middle" xml:space="preserve">doc*</text>
<text class="nj-jsonview-mono" x="585" y="670" text-anchor="middle" xml:space="preserve">node*</text>
<path class="nj-jsonview-arr nj-jsonview-c-struct" d="M515 648 L515 622" marker-end="url(#jvl-struct)"/>
<path class="nj-jsonview-arr nj-jsonview-c-struct" d="M585 648 C585 561 606 561 606 474" marker-end="url(#jvl-struct)"/>
<text class="nj-jsonview-note" x="30" y="524" xml:space="preserve">integers are converted while parsing and kept in their node;</text>
<text class="nj-jsonview-note" x="30" y="542" xml:space="preserve">floats and strings point back into the text</text>
</svg>

</div>

<p class="nj-caption" markdown>Top: the tree of separate heap allocations that `basic_json::parse()` builds. Bottom: `json_document::parse()` keeps the source text and builds one flat index of 16-byte nodes that point back into it, plus a buffer of decoded strings.</p>

## How to use it

Include `<nlohmann/json_view.hpp>` in addition to (or instead of) `<nlohmann/json.hpp>`. Parse into a
[`json_document`](../api/json_document.md), inspect its [`root()`](../api/basic_json_document/root.md), and
`materialize()` when you need a real value. `materialize()` works on any view, not just the root, so you can turn just
the subtree you need into a value:

??? example "Example: parse a document, inspect its root, and materialize it"

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // json_document is basic_json_document<nlohmann::json>: same value types
        // and containers as the ordinary json specialization
        json_document doc = json_document::parse(R"({"pi": 3.14, "numbers": [1, 2, 3]})");
    
        std::cout << doc.root().is_object() << '\n';
        std::cout << doc.root().materialize().dump() << '\n';
    }
    
    ```

    Output:

    ```json
    true
    {"numbers":[1,2,3],"pi":3.14}
    
    ```

[`ordered_json_document`](../api/ordered_json_document.md) is the equivalent for
[`ordered_json`](../api/ordered_json.md), just as [`ordered_json`](../api/ordered_json.md) is to
[`json`](../api/json.md).

## Ownership and lifetime

A document either **borrows** the text it was parsed from, or **owns** its own copy of it; call
[`owns_source()`](../api/basic_json_document/owns_source.md) to find out which happened.
[`parse()`](../api/basic_json_document/parse.md) decides this from the value category and type of its argument (an
lvalue `#!cpp std::string` is borrowed; an rvalue `#!cpp std::string` is moved in, owned without a copy; a stream is
read into an owned buffer; and so on — see [`parse`'s Notes](../api/basic_json_document/parse.md#notes) for the full
table). [`parse_copy()`](../api/basic_json_document/parse_copy.md) always owns a copy, regardless of the input.

!!! warning "A borrowed document depends on your buffer"

    If a document borrows its text, that text **must outlive the document** (and every view taken from it) and must
    stay **unmodified** for as long as the document exists, since floating-point values and unescaped strings are
    read from it lazily. Reading or writing through a view after the underlying buffer is gone is undefined behavior,
    exactly as it would be for a dangling `#!cpp std::string_view`.

A view is valid only while all of the following hold:

- the document is alive,
- the document has not been re-parsed since the view was taken (with [`read()`](../api/basic_json_document/read.md)
  or [`parse()`](../api/basic_json_document/parse.md) into it),
- the document has not had [`shrink_to_fit()`](../api/basic_json_document/shrink_to_fit.md) called on it since, and
- if the document borrows its source text, that text is still alive and unmodified.

Moving the `basic_json_document<>` itself is fine and does **not** invalidate its views: the index is a separate heap
allocation that keeps its address across the move. Take a fresh view from [`root()`](../api/basic_json_document/root.md)
whenever any of the other conditions above was not met.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-jsonview " viewBox="0 0 840 572" role="img" aria-labelledby="fig-jvt-title fig-jvt-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jvt-title">When a json_view becomes invalid</title>
<desc id="fig-jvt-title-d">Four timelines. First: a document borrows a std::string; when the string is destroyed, the document and every view taken from it dangle. Second: doc.read() re-parses the document; views taken before are invalid, a fresh view from root() is valid. Third: doc.shrink_to_fit() has the same effect. Fourth: moving the document does not invalidate its views; destroying the moved-to document does.</desc>
<defs>
<marker id="jvt-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="12" width="34" height="12" rx="3"/>
<text class="nj-jsonview-note" x="252" y="23" xml:space="preserve">alive / valid</text>
<rect class="nj-jsonview-bad" x="370" y="12" width="34" height="12" rx="3"/>
<text class="nj-jsonview-note" x="412" y="23" xml:space="preserve">dangling: using it is undefined behavior</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M210 44 L820 44"/>
<text class="nj-jsonview-tiny" x="820" y="38" text-anchor="end" xml:space="preserve">time →</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="74" xml:space="preserve">The borrowed text is destroyed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="99" text-anchor="end" xml:space="preserve">std::string text</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="87" width="260" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="127" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="115" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="115" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="155" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="330" y="143" width="140" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="143" width="350" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 82 V168"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="80" xml:space="preserve">text destroyed</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="155" xml:space="preserve">every view, and the document itself</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="202" xml:space="preserve">The document is re-parsed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="227" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="215" width="610" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="255" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="243" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="243" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="283" text-anchor="end" xml:space="preserve">v = doc.root()</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="530" y="271" width="290" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 210 V296"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="208" xml:space="preserve">doc.read(other)</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="255" xml:space="preserve">views taken before</text>
<text class="nj-jsonview-note nj-jsonview-onok" x="536" y="283" xml:space="preserve">a fresh view is valid again</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="330" xml:space="preserve">The document is shrunk</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="355" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="343" width="610" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="383" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="371" width="200" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="470" y="371" width="350" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="411" text-anchor="end" xml:space="preserve">v = doc.root()</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="530" y="399" width="290" height="16" rx="3"/>
<path class="nj-jsonview-evt" d="M470 338 V424"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="474" y="336" xml:space="preserve">doc.shrink_to_fit()</text>
<text class="nj-jsonview-note nj-jsonview-onbad" x="476" y="383" xml:space="preserve">views taken before</text>
<text class="nj-jsonview-note nj-jsonview-onok" x="536" y="411" xml:space="preserve">a fresh view is valid again</text>
<text class="nj-jsonview-h nj-jsonview-sm2" x="16" y="458" xml:space="preserve">The document is moved, then destroyed</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="483" text-anchor="end" xml:space="preserve">json_document doc</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="210" y="471" width="210" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="511" text-anchor="end" xml:space="preserve">moved = std::move(doc)</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="420" y="499" width="260" height="16" rx="3"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="198" y="539" text-anchor="end" xml:space="preserve">json_view v</text>
<rect class="nj-jsonview-bar nj-jsonview-c-struct" x="270" y="527" width="410" height="16" rx="3"/>
<rect class="nj-jsonview-bad" x="680" y="527" width="140" height="16" rx="3"/>
<path class="nj-jsonview-evt nj-jsonview-evt--ok" d="M420 466 V552"/>
<text class="nj-jsonview-tiny" x="424" y="464" xml:space="preserve">std::move: views stay valid</text>
<path class="nj-jsonview-evt" d="M680 466 V552"/>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="684" y="464" xml:space="preserve">moved is destroyed</text>
</svg>

</div>

<p class="nj-caption" markdown>Four timelines of a document and its views, each bar showing when an object is alive or valid and when it dangles. Destroying the borrowed text, re-parsing, or shrinking the document invalidates the views taken before; moving the document does not.</p>

A view can dangle, exactly like a `#!cpp std::string_view`: nothing stops you from using it after its document is
gone. This is deliberate. A view is two pointers and trivially copyable; making it safe (a `#!cpp std::shared_ptr` in
the document and a `#!cpp std::weak_ptr` in each view) would make it larger, add reference counting to every copy,
and a `lock()` to every access — exactly the costs the view exists to avoid. What is caught is the obvious case:
because a view dies with its document, [`root()`](../api/basic_json_document/root.md) is not callable on a temporary
document: `#!cpp auto v = json_document::parse(text).root();` does not compile. Give the document a name first.

??? example "Example: borrowed and owned documents, and when views become invalid"

    ```cpp
    #include <iostream>
    #include <string>
    #include <utility>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // BORROWED: doc only points into `text`; `text` must outlive `doc`
        std::string text = R"({"a": 1})";
        json_document doc = json_document::parse(text);
        std::cout << doc.owns_source() << '\n'; // false
    
        // a view is valid as long as the document is alive, has not been
        // re-parsed (read()) or shrunk (shrink_to_fit()), and -- if borrowed --
        // the source text is alive
        nlohmann::json_view v = doc.root();
        std::cout << v.is_object() << '\n';
    
        // re-parsing the SAME document invalidates views taken before the call;
        // `v` above must not be used after this line
        doc.read(R"([1, 2, 3])");
        v = doc.root(); // take a fresh view instead
        std::cout << v.is_array() << '\n';
    
        // moving the document does not invalidate views: the node index is
        // heap-allocated and does not move with the document object
        json_document moved = std::move(doc);
        std::cout << v.is_array() << '\n';
    }
    
    ```

    Output:

    ```json
    false
    true
    true
    true
    
    ```

## What is the same as `parse()`

- **Accept/reject.** [`accept()`](../api/basic_json_document/accept.md) and
  [`parse()`](../api/basic_json_document/parse.md) accept and reject exactly the same inputs as
  [`basic_json::accept()`](../api/basic_json/accept.md)/[`basic_json::parse()`](../api/basic_json/parse.md), with the
  same `ignore_comments` and `ignore_trailing_commas` options.
- **Errors.** A failing parse throws the same exception — the same id, message, and position — because on failure
  the library's own parser is run on the same bytes to produce the diagnostic. Valid input never pays for this, and
  the replay builds no values: it costs about a lexing pass up to the error.
  `#!cpp allow_exceptions == false` skips the replay and gives a
  [discarded](../api/basic_json_document/is_discarded.md) document instead of throwing, just as it gives a discarded
  value for `#!cpp basic_json::parse()`.
- **Number classification.** An integer literal that does not fit into the 64-bit integer type becomes a
  floating-point value, exactly as it does for `#!cpp basic_json::parse()`.
- **Macros.** [`JSON_STRICT_NUL_HANDLING`](../api/macros/json_strict_nul_handling.md) and
  [`JSON_NOEXCEPTION`](../api/macros/json_noexception.md)/[`JSON_THROW_USER`](../api/macros/json_throw_user.md)
  behave the same way they do for `<nlohmann/json.hpp>`. These are the macros that change what the parser accepts or
  how it reports errors. The others either do not apply ([`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md)
  needs parent pointers in `basic_json` values) or only affect the values `materialize()` produces, through
  `BasicJsonType`.

## What is different

- **Only 64-bit integers.** `basic_json_document<BasicJsonType>` requires `BasicJsonType::number_integer_t` and
  `number_unsigned_t` to both be 64 bits wide; this is a compile-time `#!cpp static_assert`.
- **A 4 GiB input limit.** An input of 4294967280 bytes (4 GiB minus 16 bytes) or more throws
  [`out_of_range.416`](../home/exceptions.md#jsonexceptionout_of_range416), a limit
  `#!cpp basic_json::parse()` does not have. It keeps an index entry at 16 bytes: offsets and counts are 32 bits
  wide. The limit is 16 bytes below 2^32, because the parser reads in 16-byte steps, and a position one step past the
  end must still fit.
- **A stream is always read to its end.** There is no partial/streaming read of an `#!cpp std::istream`: the stream
  is read to its end into a buffer the document owns, and parsing starts after that.
- **Fewer source positions after edits.** With
  [`JSON_DIAGNOSTIC_POSITIONS`](../api/macros/json_diagnostic_positions.md) enabled,
  [`materialize()`](../api/basic_json_view/materialize.md) sets the same positions as `#!cpp basic_json::parse()`.
  In an [editable document](../api/json_editable_document.md), a value written by an edit has none, and neither has
  an array or object whose elements changed or whose last element has none; a `basic_json` value keeps its positions
  when it is changed. See [`materialize()`](../api/basic_json_view/materialize.md#notes).
- **Objects iterate in document order.** [`begin()`](../api/basic_json_view/begin.md)/
  [`end()`](../api/basic_json_view/end.md) and [`items()`](../api/basic_json_view/items.md) visit an object's
  members in the order they appear in the source text. `basic_json`'s default `object_t` is a `std::map`, which
  sorts by key, so iterating a [`materialize()`](../api/basic_json_view/materialize.md)d value can print members in
  a different order than iterating the view they came from.
- **Chained access is safe.** [`operator[]`](../api/basic_json_view/operator%5B%5D.md) with a missing key, an index
  out of range, or an unresolvable JSON pointer returns a [discarded](../api/basic_json_view/is_discarded.md) view, and
  `operator[]` on a discarded view returns a discarded view without throwing: `#!cpp v["a"]["b"][0]` can be tested
  once at the end. Type errors on values that exist (a key on an array, an index on an object) still throw, and
  [`at`](../api/basic_json_view/at.md) throws for every missing value.
- **Duplicate keys: lookups find the first member, `parse()` keeps the last.** See [Duplicate keys](#duplicate-keys)
  below.
- **No [`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md) path.** Exceptions thrown by `basic_json_view`'s own
  element access and lookup functions never carry the JSON Pointer path `JSON_DIAGNOSTICS` would otherwise add: the
  view has no `basic_json` value to point at, so the exception is created without one, regardless of how
  `BasicJsonType` was built.
- **Ordering comparisons are not provided** by `basic_json_view` — there is no `#!cpp operator<`.
  [`operator==`](../api/basic_json_view/operator_eq.md) and [`operator!=`](../api/basic_json_view/operator_ne.md) are
  provided, though: two views, or a view and a `BasicJsonType` value, compare equal exactly when
  [`materialize()`](../api/basic_json_view/materialize.md) or [`parse()`](../api/basic_json/parse.md) would produce
  equal values for them, without ever building a tree to do it. For ordering, too,
  [`materialize()`](../api/basic_json_view/materialize.md) is the way to get a value you can compare.

## Duplicate keys

!!! warning "A lookup in a view and in the parsed value can give different answers"

    If an object in the source text repeats a key, [`operator[]`](../api/basic_json_view/operator%5B%5D.md),
    [`at`](../api/basic_json_view/at.md), [`find`](../api/basic_json_view/find.md),
    [`value`](../api/basic_json_view/value.md), [`contains`](../api/basic_json_view/contains.md), and JSON pointer
    resolution all return the **first** member with that key. `basic_json::parse()` instead keeps the **last** value
    of a repeated key, so for `#!cpp {"a":1,"a":2}`, `#!cpp view["a"]` is `#!cpp 1` while `#!cpp parse(text)["a"]` is
    `#!cpp 2`. [`count`](../api/basic_json_view/count.md) counts every member with the key, so it is `#!cpp 2` here.

[`begin()`](../api/basic_json_view/begin.md)/[`end()`](../api/basic_json_view/end.md) and
[`items()`](../api/basic_json_view/items.md) visit *every* occurrence, in document order, and
[`size()`](../api/basic_json_view/size.md) counts all of them, so `#!cpp view.size()` can be larger than
`#!cpp view.materialize().size()`.

**Why the first?** A lookup can stop as soon as it finds a match. Returning the last member would force every lookup
to scan all members of the object, even when the key is found at the very first one: this made lookups in small
objects 1.6 to 3.4 times slower. The hash index of the keys of objects with 128 members or more leads to the first member of a
key as well. Other zero-copy parsers that index the source text, such as yyjson and simdjson, also return the first
member. RFC 8259 only says that names within an object SHOULD be unique and that the behavior of a receiver that sees
duplicates is unpredictable, so neither choice is wrong.

The same holds for [`get<T>()`](../api/basic_json_view/get.md) of a type whose `from_json()` reads the view, such as
the types of the `NLOHMANN_DEFINE_TYPE_*` macros: their members are looked up, so `#!cpp get<point>()` of
`#!cpp {"x":1,"x":2}` reads `#!cpp x == 1`, while `#!cpp materialize().get<point>()` reads `#!cpp 2`.

**What stays the same as `parse()`?** [`materialize()`](../api/basic_json_view/materialize.md) and
[`get<std::map<...>>()`](../api/basic_json_view/get.md) replay every member in order, so they keep the *last* value
exactly like `#!cpp basic_json::parse()` (at the position of the first occurrence of the key, for an
[`ordered_json`](../api/ordered_json.md)).

**How do I get the value `parse()` would give?** Either call `#!cpp view.materialize()` and look the key up in the
result, or iterate the members and keep the last match:

```cpp
// the last member with the key "a", as parse() would keep it
json_view last;
for (const auto item : view.items())
{
    if (item.key() == "a")
    {
        last = item.value();
    }
}
```

If you cannot trust the source text to have unique keys, check [`size()`](../api/basic_json_view/size.md) against the
number of distinct keys, or reject duplicates when iterating.

## Getting values out without copying

[`get<T>()`](../api/basic_json_view/get.md) converts most `T` directly from the flat index, without ever building a
`basic_json` value for the conversion: `#!cpp bool`, arithmetic types, `#!cpp std::nullptr_t`,
`#!cpp std::string`/other `#!cpp std::basic_string`s (copied once), `basic_json_view` itself, the standard containers
and other types the library converts (`#!cpp std::vector`, `#!cpp std::map`, `#!cpp std::list`, `#!cpp std::array`,
`#!cpp std::pair`, `#!cpp std::tuple`, `#!cpp std::optional`, ...), and the types of the `NLOHMANN_DEFINE_TYPE_*` and
`NLOHMANN_JSON_SERIALIZE_ENUM` macros. Types whose `from_json()` is written for `basic_json` only go through
[`materialize()`](../api/basic_json_view/materialize.md)`.get<T>()` instead: the subtree is built into a real
`basic_json` value first, exactly as [`parse()`](../api/basic_json/parse.md) would, and converted from there. See
[Writing generic code](#writing-generic-code) for how to write a `from_json()` that reads views.

Two conversions never copy at all:

- [`get_string()`](../api/basic_json_view/get_string.md) (equivalently, `#!cpp get<string_view_t>()`) returns a
  string as a `string_view_t` pointing into the document's [`source()`](../api/basic_json_document/source.md) text —
  or, for a string that contains escape sequences, into the document's own buffer of decoded strings — instead of
  allocating a new `#!cpp std::string`.
- [`number_token()`](../api/basic_json_view/number_token.md) returns a number exactly as it was written in the
  source, e.g. `#!cpp "1.50"`, `#!cpp "1E2"`, or an integer with more digits than any number type holds, instead of
  rounding it into a `#!cpp double`/`#!cpp int64_t` the way `#!cpp get<T>()` (and
  [`basic_json::parse()`](../api/basic_json/parse.md)) would.

Both results are only valid as long as the view — and, for a string with no escapes, the borrowed source text — is.

## Writing generic code

A view's type names its `BasicJsonType` and its [`view_mode`](../api/view_mode.md):
[`json_view`](../api/json_view.md) is `#!cpp basic_json_view<json, view_mode::read_only>`, and
[`json_editable_view`](../api/json_editable_view.md) is `#!cpp basic_json_view<json, view_mode::editable>`. These are
different types. The only conversion between them turns a view of a read-only document into a view of an editable
document of the same `BasicJsonType`, so a function written for one shortcut accepts few other views:

```cpp
void print_names(json_view v);           // accepts neither an ordered_json_view nor a json_editable_view
void print_names(json_editable_view v);  // also accepts a json_view, but no ordered_json_view
```

This is the same pitfall as a `to_json`/`from_json` written for `json` instead of any `BasicJsonType`, which then does
not work for `ordered_json`. The shortcuts are for declaring documents and views; a function that takes a view names
the views it accepts with a template:

```cpp
// views of editable documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::editable> v);

// views of read-only documents only
template<typename BasicJsonType>
void f(basic_json_view<BasicJsonType, view_mode::read_only> v);

// views of either document type
template<typename BasicJsonType, view_mode Mode>
void f(basic_json_view<BasicJsonType, Mode> v);
```

Views are passed by value: they are two pointers, cheap to copy, like a `#!cpp std::string_view`. A `const&` works as
well, but a non-`const` reference does not bind to the views that [`root()`](../api/basic_json_document/root.md),
[`operator[]`](../api/basic_json_view/operator%5B%5D.md), and [`at()`](../api/basic_json_view/at.md) return, so
`#!cpp f(doc.root())` would not compile.

There is no conversion from an editable view to a read-only one, by design: the mode decides how a view walks the
index. A read-only view reads a container in place, while a view of an editable document follows the links that edits
leave behind, so a read-only view of an edited document would read stale values. The other direction is safe: a
read-only document has no edits, so a view of it [converts](../api/basic_json_view/basic_json_view.md) to an
editable view, which reads it like an editable document before its first edit. A template deduces the mode without
conversions, so the template forms above still accept only the modes they name. Views of both modes compare with
[`operator==`](../api/basic_json_view/operator_eq.md).

[`is_json_view<T>`](../api/is_json_view.md) tells views from other types, for constraints that cannot be written as a
`basic_json_view<...>` parameter.

### A `from_json()` that reads views

[`get<T>()`](../api/basic_json_view/get.md) on a view calls `T`'s `from_json()` with the view itself if that
`from_json()` accepts views, and with [`materialize()`](../api/basic_json_view/materialize.md) otherwise. The
`from_json()` functions of the [`NLOHMANN_DEFINE_TYPE_*`](../api/macros/nlohmann_define_type_intrusive.md),
[`NLOHMANN_DEFINE_DERIVED_TYPE_*`](../api/macros/nlohmann_define_derived_type.md), and
[`NLOHMANN_JSON_SERIALIZE_ENUM`](../api/macros/nlohmann_json_serialize_enum.md) macros, and those of the library
for the standard types, accept views, so these types need nothing else. For decoding the statuses of
twitter.json into structs, reading the view is about 5 times faster than `#!cpp materialize().get<T>()`.

A hand-written `from_json()` reads views if it is constrained to `json` values and views:

```cpp
template < typename J, typename std::enable_if <
               nlohmann::is_json_view<J>::value || std::is_same<J, nlohmann::json>::value, int >::type = 0 >
void from_json(const J& j, person& p)
{
    p.name = j.at("name").template get<std::string>();
    p.age = j.at("age").template get<int>();
}
```

Its body may only use what views and `basic_json` have in common: the type checks, `at()`, `operator[]`, `contains()`,
`value()`, `size()`, iteration and `items()`, and `get<T>()`/`get_to()`. An unconstrained
`#!cpp template<typename BasicJsonType> void from_json(const BasicJsonType& j, person& p)`, as in
[arbitrary type conversions](arbitrary_types.md), is never called with a view, as it might use `basic_json` functions
a view does not have; such a type is converted through `materialize()`. A `from_json()` for `json` only is
converted through `materialize()` as well.

Two things differ when a `from_json()` reads the view:

- **Duplicate keys.** Members looked up by name (`at()`, `value()`, ... and thus the macros) find the **first** member
  with a repeated key, see [Duplicate keys](#duplicate-keys); `#!cpp materialize().get<T>()` would see the last one.
  Containers built from an object, such as `#!cpp std::map`, keep the **last** value either way, as
  [`parse()`](../api/basic_json/parse.md) does.
- **[`JSON_DIAGNOSTICS`](../api/macros/json_diagnostics.md).** Exceptions thrown by the view carry no path to the
  value.

`to_json()` is unaffected: it writes `basic_json` values, never views.

## Writing a view back

[`dump()`](../api/basic_json_view/dump.md) serializes a view directly from the flat index, without ever building a
`basic_json` value. An object's members are written in document order, not sorted by key, and *every* occurrence of a
repeated key is written, not only the last one — the same two ways [iteration](#what-is-different) already differs
from a [`materialize()`](../api/basic_json_view/materialize.md)d value, see [Duplicate keys](#duplicate-keys).
`#!cpp materialize().dump()` gives a different result in both respects for a `json_view`.

By default, numbers are written the way [`basic_json::dump()`](../api/basic_json/dump.md) would.
[`number_format::source`](../api/basic_json_view/number_format.md) instead copies every number exactly as it was
written in the source text — a price like `#!cpp 19.90`, a long order or account ID with more digits than any number
type holds, or a high-precision coordinate — something `basic_json` cannot do at all, since parsing already reduces
a number to its parsed `#!cpp double`/`#!cpp int64_t` value.

[`operator<<`](../api/basic_json_view/operator_ltlt.md) writes a view to a stream the way `basic_json`'s does, using
the stream's `width`/`fill` for indentation.

## Editing a document

Everything above is read-only: a `json_document`/`json_view` lets you look at a parsed text without copying it, but
not change it. [`basic_json_document<BasicJsonType, view_mode::editable>`](../api/basic_json_document/index.md) — more conveniently
spelled [`json_editable_document`](../api/json_editable_document.md) or
[`ordered_json_editable_document`](../api/ordered_json_editable_document.md) — also lets you
[`set`](../api/basic_json_document/set.md) a value, [`push_back`](../api/basic_json_document/push_back.md) onto or
[`insert`](../api/basic_json_document/insert.md) into an array, and [`erase`](../api/basic_json_document/erase.md)
an object member or an array element, still without ever building a `basic_json` tree for parts you do not touch.

The [mode](../api/view_mode.md) defaults to `#!cpp view_mode::read_only`, so `json_document`/`ordered_json_document` are unaffected — they carry
none of the bookkeeping edits need, and calling `set`/`push_back`/`insert`/`erase` on one is a compile error, not a
runtime one.

### Why: editing without reformatting

The `#!cpp 19.90` price from [above](#writing-a-view-back) is exactly the kind of value that makes editing a `json`
or `ordered_json` value in place lossy. Say you parse a configuration file, patch one field, and write it back:

- **`json`** re-sorts every key on the way in (`object_t` is a `#!cpp std::map`) and rewrites every number to its
  shortest round-trip form on the way out — a one-field patch turns into a diff that reorders the whole file and
  rewrites `#!cpp 19.90` to `#!cpp 19.9`.
- **`ordered_json`** keeps the key order, but still rewrites every number the same way: parsing has already reduced
  it to a `#!cpp double`/`#!cpp int64_t`, and there is no way back to how it was spelled in the source text.

The patch of the example below (set `"host"`, add `"retries"`) written back by each of them:

<div class="nj-jsonview-cmp" role="group" aria-label="The same patch written back by json, ordered_json, and json_editable_document">
<div><p class="nj-jsonview-cmp-h"><code>json</code></p><p class="nj-jsonview-cmp-v">keys sorted, numbers rewritten</p><pre>{<span class="nj-jsonview-bad">"host"</span>:"db2",
 "name":"cache",
 "port":6379,
 "price":<span class="nj-jsonview-bad">19.9</span>,
 "retries":3}</pre></div>
<div><p class="nj-jsonview-cmp-h"><code>ordered_json</code></p><p class="nj-jsonview-cmp-v">key order kept, numbers rewritten</p><pre>{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":<span class="nj-jsonview-bad">19.9</span>,
 "retries":3}</pre></div>
<div class="nj-jsonview-cmp--best"><p class="nj-jsonview-cmp-h"><code>json_editable_document</code></p><p class="nj-jsonview-cmp-v">order and spelling kept</p><pre>{"name":"cache",
 "host":"db2",
 "port":6379,
 "price":<span class="nj-jsonview-ok">19.90</span>,
 "retries":3}</pre></div>
</div>

An editable document keeps both. [`dump()`](../api/basic_json_view/dump.md) of an edited document writes members in
document order — a member [`set`](../api/basic_json_document/set.md) added goes at the end, exactly where it was
inserted, and an [`erase`](../api/basic_json_document/erase.md)d member simply leaves a gap: everything around it
keeps its place — and [`number_format::source`](../api/basic_json_view/number_format.md) keeps the exact spelling
of every number an edit did not itself touch; a number an edit *did* touch is written the way
[`BasicJsonType::dump()`](../api/basic_json/dump.md) would write it, since there is no source spelling for a brand
new value.

??? example "Example: patch a configuration, keeping member order and number spellings"

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json;
    using nlohmann::json_editable_document;
    using nlohmann::json_editable_view;
    
    int main()
    {
        // a configuration file, as it might be read from disk
        const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "price": 19.90})";
        std::cout << text << "\n\n";
    
        // patch two fields -- "price" is never touched
        json_editable_document doc = json_editable_document::parse(text);
        doc.set(doc.root(), "host", "db2");
        doc.set(doc.root(), "retries", 3);
    
        // member order (the new member at the end) and the untouched number's
        // exact spelling survive
        std::cout << doc.root().dump(-1, ' ', false, json_editable_view::number_format::source) << '\n';
    
        // the same patch on a plain json value: keys are sorted (object_t is a
        // std::map), and "price" is rewritten even though the patch never
        // touched it
        json plain = json::parse(text);
        plain["host"] = "db2";
        plain["retries"] = 3;
        std::cout << plain.dump() << '\n';
    }
    
    ```

    Output:

    ```json
    {"name": "cache", "host": "db1", "port": 6379, "price": 19.90}
    
    {"name":"cache","host":"db2","port":6379,"price":19.90,"retries":3}
    {"host":"db2","name":"cache","port":6379,"price":19.9,"retries":3}
    
    ```

### What stays valid, and what an edit costs

The source text itself is **never written**, and the parsed index never moves — a value keeps the node it was
parsed into for as long as it is not itself replaced. So every [view](../api/basic_json_view/index.md) taken before
an edit, including a previously obtained [`root()`](../api/basic_json_document/root.md), stays valid and, if it
still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing
what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does
invalidate is the **iterators** taken over an edited array or object: the first time an element is added to it,
inserted into it, erased from it, or replaced by a value that spans a different number of nodes, its elements move from the parsed, fixed layout to a growable block of links
so that [`push_back`](../api/basic_json_document/push_back.md) can later grow it in amortized constant time —
existing elements are not touched, but an iterator that was walking the old layout no longer matches. A string
obtained with
[`get_string()`](../api/basic_json_view/get_string.md) is unaffected either way and stays valid across further
edits. See [`basic_json_document`'s Edits](../api/basic_json_document/index.md#edits) for the details, and
[`set`'s Exception safety](../api/basic_json_document/set.md#exception-safety) for what an edit guarantees if it
throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in
the index is described in the [architecture overview](../home/architecture.md#node-index-of-json-views).

Step through the edits of a small document (the node fields follow the [architecture overview](../home/architecture.md#node-index-of-json-views)):

<div class="nj-jsonview-steps" data-nj-jsonview-steps>
<figure class="nj-jsonview-step" data-label="After parsing">
<div class="nj-jsonview-scroll">
<svg class="nj-fig nj-jsonview nj-jsonview-editfig" viewBox="0 0 840 372" role="img" aria-labelledby="fig-jve0-title fig-jve0-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jve0-title">Step 1 of 5: parsed</title>
<desc id="fig-jve0-title-d">After parse: nine nodes, nothing owned yet. The dump with number_format::source is {&quot;port&quot;:6379,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;eu&quot;,&quot;a\&quot;b&quot;]}.</desc>
<defs>
<marker id="jve0-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve0-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve0-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve0-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-note nj-jsonview-strong" x="16" y="22" xml:space="preserve">parsed index: fixed, never moves</text>
<text class="nj-jsonview-note" x="824" y="22" text-anchor="end" xml:space="preserve">the source text is never written</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="47" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="78" y="61" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="78" y="77" text-anchor="middle" xml:space="preserve">{ } 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="47" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="166" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="166" y="77" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="212" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="47" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="254" y="61" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="254" y="77" text-anchor="middle" xml:space="preserve">6379</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="47" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="342" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="342" y="77" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="47" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="430" y="61" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="430" y="77" text-anchor="middle" xml:space="preserve">19.90</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="47" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="518" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="518" y="77" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="47" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="606" y="61" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="606" y="77" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="652" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="47" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="694" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="694" y="77" text-anchor="middle" xml:space="preserve">&quot;eu&quot;</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="47" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-dec" x="782" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="782" y="77" text-anchor="middle" xml:space="preserve">a&quot;b</text>
<text class="nj-jsonview-note nj-jsonview-strong nj-jsonview-c-own" x="16" y="288" xml:space="preserve">owned storage: allocated on demand, never moves</text>
<rect class="nj-jsonview-store" x="10" y="192" width="820" height="54" rx="8"/>
<text class="nj-jsonview-note" x="26" y="224" xml:space="preserve">empty: a read-only json_document has none of this</text>
<path class="nj-jsonview-sep" d="M16 300 H824"/>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="318" xml:space="preserve">view v = root()[&quot;tags&quot;] (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="318" xml:space="preserve">valid, sees every edit</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="338" xml:space="preserve">iterator over tags (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="338" xml:space="preserve">valid</text>
<text class="nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted" x="16" y="360" xml:space="preserve">dump(): {&quot;port&quot;:6379,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;eu&quot;,&quot;a\&quot;b&quot;]}</text>
</svg>

</div>
<figcaption>Step 1 of 5. After parsing: nine nodes in the parsed index, no owned storage yet.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set an existing member">
<div class="nj-jsonview-scroll">
<svg class="nj-fig nj-jsonview nj-jsonview-editfig" viewBox="0 0 840 372" role="img" aria-labelledby="fig-jve1-title fig-jve1-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jve1-title">Step 2 of 5: doc.set(doc.root(), &quot;port&quot;, 6380)</title>
<desc id="fig-jve1-title-d">set: the node of the integer is overwritten in place. The dump with number_format::source is {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;eu&quot;,&quot;a\&quot;b&quot;]}.</desc>
<defs>
<marker id="jve1-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve1-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve1-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve1-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-note nj-jsonview-strong" x="16" y="22" xml:space="preserve">parsed index: fixed, never moves</text>
<text class="nj-jsonview-note" x="824" y="22" text-anchor="end" xml:space="preserve">the source text is never written</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="47" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="78" y="61" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="78" y="77" text-anchor="middle" xml:space="preserve">{ } 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="47" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="166" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="166" y="77" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-num" x="212" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="47" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="254" y="61" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="254" y="77" text-anchor="middle" xml:space="preserve">6380</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="47" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="342" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="342" y="77" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="47" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="430" y="61" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="430" y="77" text-anchor="middle" xml:space="preserve">19.90</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="47" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="518" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="518" y="77" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="47" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="606" y="61" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="606" y="77" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="652" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="47" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="694" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="694" y="77" text-anchor="middle" xml:space="preserve">&quot;eu&quot;</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="47" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-dec" x="782" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="782" y="77" text-anchor="middle" xml:space="preserve">a&quot;b</text>
<text class="nj-jsonview-note nj-jsonview-strong nj-jsonview-c-own" x="16" y="288" xml:space="preserve">owned storage: allocated on demand, never moves</text>
<rect class="nj-jsonview-store" x="10" y="192" width="820" height="54" rx="8"/>
<text class="nj-jsonview-note" x="26" y="224" xml:space="preserve">empty: a read-only json_document has none of this</text>
<path class="nj-jsonview-sep" d="M16 300 H824"/>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="318" xml:space="preserve">view v = root()[&quot;tags&quot;] (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="318" xml:space="preserve">valid, sees every edit</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="338" xml:space="preserve">iterator over tags (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="338" xml:space="preserve">valid</text>
<text class="nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted" x="16" y="360" xml:space="preserve">dump(): {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;eu&quot;,&quot;a\&quot;b&quot;]}</text>
</svg>

</div>
<figcaption>Step 2 of 5. <code>doc.set(doc.root(), "port", 6380)</code> overwrites the node of the integer in place; no member is added or removed, so the object keeps its parsed layout.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="erase an array element">
<div class="nj-jsonview-scroll">
<svg class="nj-fig nj-jsonview nj-jsonview-editfig" viewBox="0 0 840 372" role="img" aria-labelledby="fig-jve2-title fig-jve2-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jve2-title">Step 3 of 5: doc.erase(doc.root()[&quot;tags&quot;], 0)</title>
<desc id="fig-jve2-title-d">erase: the array moves to a block of links in owned storage. The dump with number_format::source is {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;]}.</desc>
<defs>
<marker id="jve2-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve2-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve2-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve2-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-note nj-jsonview-strong" x="16" y="22" xml:space="preserve">parsed index: fixed, never moves</text>
<text class="nj-jsonview-note" x="824" y="22" text-anchor="end" xml:space="preserve">the source text is never written</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="47" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="78" y="61" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="78" y="77" text-anchor="middle" xml:space="preserve">{ } 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="47" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="166" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="166" y="77" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="212" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="47" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="254" y="61" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="254" y="77" text-anchor="middle" xml:space="preserve">6380</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="47" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="342" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="342" y="77" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="47" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="430" y="61" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="430" y="77" text-anchor="middle" xml:space="preserve">19.90</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="47" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="518" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="518" y="77" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="47" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="606" y="61" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-tiny nj-jsonview-c-struct nj-jsonview-strong" x="643" y="47" text-anchor="end" xml:space="preserve">moved</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="606" y="77" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-gap nj-jsonview-c-str" x="652" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="47" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="694" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="694" y="77" text-anchor="middle" xml:space="preserve">&quot;eu&quot;</text>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="694" y="98" text-anchor="middle" xml:space="preserve">unreferenced</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="47" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-dec" x="782" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="782" y="77" text-anchor="middle" xml:space="preserve">a&quot;b</text>
<text class="nj-jsonview-note nj-jsonview-strong nj-jsonview-c-own" x="16" y="288" xml:space="preserve">owned storage: allocated on demand, never moves</text>
<rect class="nj-jsonview-store" x="10" y="192" width="820" height="54" rx="8"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-struct" x="16" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="66" y="207" text-anchor="end" xml:space="preserve">0&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="43" y="220" text-anchor="middle" xml:space="preserve">header</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="43" y="235" text-anchor="middle" xml:space="preserve">[ ] 1</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="73" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="123" y="207" text-anchor="end" xml:space="preserve">1&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="100" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="100" y="235" text-anchor="middle" xml:space="preserve">→ 8</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M100 196 C100 140 782 140 782 84" marker-end="url(#jve2-own)"/>
<rect class="nj-jsonview-node nj-jsonview-free nj-jsonview-c-own" x="130" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="157" y="224" text-anchor="middle" xml:space="preserve">free</text>
<path class="nj-jsonview-arr nj-jsonview-c-struct nj-jsonview-dash" d="M598 84 C598 140 43 140 43 196" marker-end="url(#jve2-struct)"/>
<path class="nj-jsonview-sep" d="M16 300 H824"/>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="318" xml:space="preserve">view v = root()[&quot;tags&quot;] (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="318" xml:space="preserve">valid, sees every edit</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="338" xml:space="preserve">iterator over tags (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-bad nj-jsonview-strong" x="320" y="338" xml:space="preserve">invalid: tags no longer uses the parsed layout</text>
<text class="nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted" x="16" y="360" xml:space="preserve">dump(): {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;]}</text>
</svg>

</div>
<figcaption>Step 3 of 5. <code>doc.erase(doc.root()["tags"], 0)</code>: the array is edited for the first time, so its elements move to a block of links in owned storage. The node of <code>"eu"</code> stays in the index, but nothing refers to it any more; iterators over the array taken before are invalid.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="push_back onto the array">
<div class="nj-jsonview-scroll">
<svg class="nj-fig nj-jsonview nj-jsonview-editfig" viewBox="0 0 840 372" role="img" aria-labelledby="fig-jve3-title fig-jve3-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jve3-title">Step 4 of 5: doc.push_back(doc.root()[&quot;tags&quot;], &quot;new&quot;)</title>
<desc id="fig-jve3-title-d">push_back: a new node, and a link appended to the block. The dump with number_format::source is {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;,&quot;new&quot;]}.</desc>
<defs>
<marker id="jve3-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve3-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve3-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve3-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-note nj-jsonview-strong" x="16" y="22" xml:space="preserve">parsed index: fixed, never moves</text>
<text class="nj-jsonview-note" x="824" y="22" text-anchor="end" xml:space="preserve">the source text is never written</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="47" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="78" y="61" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="78" y="77" text-anchor="middle" xml:space="preserve">{ } 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="47" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="166" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="166" y="77" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="212" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="47" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="254" y="61" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="254" y="77" text-anchor="middle" xml:space="preserve">6380</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="47" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="342" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="342" y="77" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="47" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="430" y="61" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="430" y="77" text-anchor="middle" xml:space="preserve">19.90</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="47" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="518" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="518" y="77" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="47" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="606" y="61" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-tiny nj-jsonview-c-struct nj-jsonview-strong" x="643" y="47" text-anchor="end" xml:space="preserve">moved</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="606" y="77" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-gap nj-jsonview-c-str" x="652" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="47" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="694" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="694" y="77" text-anchor="middle" xml:space="preserve">&quot;eu&quot;</text>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="694" y="98" text-anchor="middle" xml:space="preserve">unreferenced</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="47" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-dec" x="782" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="782" y="77" text-anchor="middle" xml:space="preserve">a&quot;b</text>
<text class="nj-jsonview-note nj-jsonview-strong nj-jsonview-c-own" x="16" y="288" xml:space="preserve">owned storage: allocated on demand, never moves</text>
<rect class="nj-jsonview-store" x="10" y="192" width="820" height="54" rx="8"/>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="16" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="66" y="207" text-anchor="end" xml:space="preserve">0&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="43" y="220" text-anchor="middle" xml:space="preserve">header</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="43" y="235" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-c-own" x="73" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="123" y="207" text-anchor="end" xml:space="preserve">1&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="100" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="100" y="235" text-anchor="middle" xml:space="preserve">→ 8</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M100 196 C100 140 782 140 782 84" marker-end="url(#jve3-own)"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="130" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="180" y="207" text-anchor="end" xml:space="preserve">2&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="157" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="157" y="235" text-anchor="middle" xml:space="preserve">→ 3&#x27;</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M157 242 C157 268 214 268 214 244" marker-end="url(#jve3-own)"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-str" x="187" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="237" y="207" text-anchor="end" xml:space="preserve">3&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="214" y="220" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="214" y="235" text-anchor="middle" xml:space="preserve">&quot;new&quot;</text>
<path class="nj-jsonview-arr nj-jsonview-c-struct nj-jsonview-dash" d="M598 84 C598 140 43 140 43 196" marker-end="url(#jve3-struct)"/>
<text class="nj-jsonview-note" x="588" y="282" text-anchor="end" xml:space="preserve">edited text</text>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="596" y="264" width="42" height="26" rx="4"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="602" y="282" xml:space="preserve">new</text>
<path class="nj-jsonview-sep" d="M16 300 H824"/>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="318" xml:space="preserve">view v = root()[&quot;tags&quot;] (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="318" xml:space="preserve">valid, sees every edit</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="338" xml:space="preserve">iterator over tags (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-bad nj-jsonview-strong" x="320" y="338" xml:space="preserve">invalid: tags no longer uses the parsed layout</text>
<text class="nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted" x="16" y="360" xml:space="preserve">dump(): {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;,&quot;new&quot;]}</text>
</svg>

</div>
<figcaption>Step 4 of 5. <code>doc.push_back(doc.root()["tags"], "new")</code>: the new string gets its own node, its text goes to the buffer of edited text, and a link to it is appended to the block of the array.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set a new member">
<div class="nj-jsonview-scroll">
<svg class="nj-fig nj-jsonview nj-jsonview-editfig" viewBox="0 0 840 372" role="img" aria-labelledby="fig-jve4-title fig-jve4-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jve4-title">Step 5 of 5: doc.set(doc.root(), &quot;retries&quot;, 3)</title>
<desc id="fig-jve4-title-d">set of a new member: the object moves to a block as well. The dump with number_format::source is {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;,&quot;new&quot;],&quot;retries&quot;:3}.</desc>
<defs>
<marker id="jve4-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve4-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve4-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jve4-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-note nj-jsonview-strong" x="16" y="22" xml:space="preserve">parsed index: fixed, never moves</text>
<text class="nj-jsonview-note" x="824" y="22" text-anchor="end" xml:space="preserve">the source text is never written</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="36" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="42" y="47" xml:space="preserve">0</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="78" y="61" text-anchor="middle" xml:space="preserve">object</text>
<text class="nj-jsonview-tiny nj-jsonview-c-struct nj-jsonview-strong" x="115" y="47" text-anchor="end" xml:space="preserve">moved</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="78" y="77" text-anchor="middle" xml:space="preserve">{ } 3</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="124" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="130" y="47" xml:space="preserve">1</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="166" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="166" y="77" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="212" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="218" y="47" xml:space="preserve">2</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="254" y="61" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="254" y="77" text-anchor="middle" xml:space="preserve">6380</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="300" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="306" y="47" xml:space="preserve">3</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="342" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="342" y="77" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="47" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="430" y="61" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="430" y="77" text-anchor="middle" xml:space="preserve">19.90</text>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="47" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="518" y="61" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="518" y="77" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="564" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="570" y="47" xml:space="preserve">6</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="606" y="61" text-anchor="middle" xml:space="preserve">array</text>
<text class="nj-jsonview-tiny nj-jsonview-c-struct nj-jsonview-strong" x="643" y="47" text-anchor="end" xml:space="preserve">moved</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="606" y="77" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-gap nj-jsonview-c-str" x="652" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="658" y="47" xml:space="preserve">7</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="694" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="694" y="77" text-anchor="middle" xml:space="preserve">&quot;eu&quot;</text>
<text class="nj-jsonview-tiny nj-jsonview-c-bad" x="694" y="98" text-anchor="middle" xml:space="preserve">unreferenced</text>
<rect class="nj-jsonview-node nj-jsonview-c-dec" x="740" y="34" width="84" height="50" rx="5"/>
<text class="nj-jsonview-tiny" x="746" y="47" xml:space="preserve">8</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-dec" x="782" y="61" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-sm" x="782" y="77" text-anchor="middle" xml:space="preserve">a&quot;b</text>
<text class="nj-jsonview-note nj-jsonview-strong nj-jsonview-c-own" x="16" y="288" xml:space="preserve">owned storage: allocated on demand, never moves</text>
<rect class="nj-jsonview-store" x="10" y="192" width="820" height="54" rx="8"/>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="16" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="66" y="207" text-anchor="end" xml:space="preserve">0&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="43" y="220" text-anchor="middle" xml:space="preserve">header</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="43" y="235" text-anchor="middle" xml:space="preserve">[ ] 2</text>
<rect class="nj-jsonview-node nj-jsonview-c-own" x="73" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="123" y="207" text-anchor="end" xml:space="preserve">1&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="100" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="100" y="235" text-anchor="middle" xml:space="preserve">→ 8</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M100 196 C100 140 782 140 782 84" marker-end="url(#jve4-own)"/>
<rect class="nj-jsonview-node nj-jsonview-c-own" x="130" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="180" y="207" text-anchor="end" xml:space="preserve">2&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="157" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="157" y="235" text-anchor="middle" xml:space="preserve">→ 3&#x27;</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M157 242 C157 268 214 268 214 244" marker-end="url(#jve4-own)"/>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="187" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="237" y="207" text-anchor="end" xml:space="preserve">3&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-str" x="214" y="220" text-anchor="middle" xml:space="preserve">string</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="214" y="235" text-anchor="middle" xml:space="preserve">&quot;new&quot;</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-num" x="244" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="294" y="207" text-anchor="end" xml:space="preserve">4&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-num" x="271" y="220" text-anchor="middle" xml:space="preserve">uint</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="271" y="235" text-anchor="middle" xml:space="preserve">3</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-struct" x="301" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="351" y="207" text-anchor="end" xml:space="preserve">5&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-struct" x="328" y="220" text-anchor="middle" xml:space="preserve">header</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="328" y="235" text-anchor="middle" xml:space="preserve">{ } 4</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-key" x="358" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="408" y="207" text-anchor="end" xml:space="preserve">6&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="385" y="220" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="385" y="235" text-anchor="middle" xml:space="preserve">port</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="415" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="465" y="207" text-anchor="end" xml:space="preserve">7&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="442" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="442" y="235" text-anchor="middle" xml:space="preserve">→ 2</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M442 196 C442 140 254 140 254 84" marker-end="url(#jve4-own)"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-key" x="472" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="522" y="207" text-anchor="end" xml:space="preserve">8&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="499" y="220" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="499" y="235" text-anchor="middle" xml:space="preserve">price</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="529" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="579" y="207" text-anchor="end" xml:space="preserve">9&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="556" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="556" y="235" text-anchor="middle" xml:space="preserve">→ 4</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M556 196 C556 140 430 140 430 84" marker-end="url(#jve4-own)"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-key" x="586" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="636" y="207" text-anchor="end" xml:space="preserve">10&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="613" y="220" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="613" y="235" text-anchor="middle" xml:space="preserve">tags</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="643" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="693" y="207" text-anchor="end" xml:space="preserve">11&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="670" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="670" y="235" text-anchor="middle" xml:space="preserve">→ 6</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M670 196 C670 140 614 140 614 84" marker-end="url(#jve4-own)"/>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-key" x="700" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="750" y="207" text-anchor="end" xml:space="preserve">12&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-key" x="727" y="220" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="727" y="235" text-anchor="middle" xml:space="preserve">retries</text>
<rect class="nj-jsonview-node nj-jsonview-hot nj-jsonview-c-own" x="757" y="196" width="54" height="46" rx="5"/>
<text class="nj-jsonview-tiny" x="807" y="207" text-anchor="end" xml:space="preserve">13&#x27;</text>
<text class="nj-jsonview-kind nj-jsonview-xs nj-jsonview-c-own" x="784" y="220" text-anchor="middle" xml:space="preserve">link</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="784" y="235" text-anchor="middle" xml:space="preserve">→ 4&#x27;</text>
<path class="nj-jsonview-arr nj-jsonview-c-own" d="M784 242 C784 268 271 268 271 244" marker-end="url(#jve4-own)"/>
<path class="nj-jsonview-arr nj-jsonview-c-struct nj-jsonview-dash" d="M598 84 C598 140 43 140 43 196" marker-end="url(#jve4-struct)"/>
<path class="nj-jsonview-arr nj-jsonview-c-struct nj-jsonview-dash" d="M70 84 C70 140 328 140 328 196" marker-end="url(#jve4-struct)"/>
<text class="nj-jsonview-note" x="588" y="282" text-anchor="end" xml:space="preserve">edited text</text>
<rect class="nj-jsonview-node nj-jsonview-c-str" x="596" y="264" width="112" height="26" rx="4"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="602" y="282" xml:space="preserve">newretries</text>
<path class="nj-jsonview-sep" d="M16 300 H824"/>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="318" xml:space="preserve">view v = root()[&quot;tags&quot;] (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-struct nj-jsonview-strong" x="320" y="318" xml:space="preserve">valid, sees every edit</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="16" y="338" xml:space="preserve">iterator over tags (taken after parse):</text>
<text class="nj-jsonview-note nj-jsonview-c-bad nj-jsonview-strong" x="320" y="338" xml:space="preserve">invalid: tags no longer uses the parsed layout</text>
<text class="nj-jsonview-mono nj-jsonview-xs nj-jsonview-muted" x="16" y="360" xml:space="preserve">dump(): {&quot;port&quot;:6380,&quot;price&quot;:19.90,&quot;tags&quot;:[&quot;a\&quot;b&quot;,&quot;new&quot;],&quot;retries&quot;:3}</text>
</svg>

</div>
<figcaption>Step 5 of 5. <code>doc.set(doc.root(), "retries", 3)</code>: a new member, so the object moves to a block too: copies of its keys, links to the values it already had, then the new key and a link to the new integer.</figcaption>
</figure>
</div>

<p class="nj-caption" markdown>The node index and the owned storage of the document after each of five edits. Use *Back*, *Next*, or the numbered buttons to switch between the steps; without JavaScript all steps are shown one below the other.</p>

## Images

[`save()`](../api/basic_json_document/save.md) writes a document as an *image*: a byte buffer that
[`load()`](../api/basic_json_document/load.md) reads back into a document without parsing — no lexing, no building
the node index, nothing but copying the nodes and pointing the text and the decoded strings at the image. Where
[`parse_copy()`](../api/basic_json_document/parse_copy.md) still has to scan the whole input,
[`load()`](../api/basic_json_document/load.md) turns that scan into a copy of the node index alone.

**Why.** A document that is parsed once and then read many times — a configuration loaded at startup, a template
rendered on every request, a large reference dataset a worker process needs in memory — pays for parsing once but
can amortize [`save()`](../api/basic_json_document/save.md)'s cost across every later load. That makes images useful
for a cache: save a document the first time it is parsed (to a file, a shared-memory segment, an in-process cache),
and [`load()`](../api/basic_json_document/load.md) it on every later use instead of parsing the source text again.
They are just as useful for handing a parsed document to another process (or a forked worker) running the same build
of the library, since [`load()`](../api/basic_json_document/load.md) turns the transfer into a copy of the node index
plus pointers into the received bytes, not a re-parse.

**Choosing a check.** [`load()`](../api/basic_json_document/load.md) takes an
[`image_check`](../api/basic_json_document/load.md#image_check) that trades validation against speed:
`image_check::full` (the default) checks everything the parser itself guarantees, so a checked image is exactly as
safe to read and serialize as a freshly parsed document — the right choice whenever the image did not come straight
from this process's own [`save()`](../api/basic_json_document/save.md), such as a file or a network peer.
`image_check::bounds` only checks structure and bounds — cheaper, since it skips scanning the text and the decoded
strings — and fits a cache the process trusts, one it wrote and reads back itself. `image_check::none` skips
validation entirely, for an image trusted as much as the process's own memory. See
[`load()`'s Notes](../api/basic_json_document/load.md#notes) for exactly what each level does and does not guarantee.

??? example "Example: cache a parsed configuration as an image"

    ```cpp
    #include <cstdint>
    #include <iostream>
    #include <string>
    #include <vector>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // a configuration a service parses once and then caches as an image, so
        // that later requests can load() it instead of parsing the text again
        const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "replicas": ["db2", "db3"]})";
        const json_document config = json_document::parse(text);
    
        // save() turns the parsed document into a byte buffer: a 64-byte header,
        // the node index, the source text, and the decoded strings
        const std::vector<std::uint8_t> image = config.save();
        std::cout << image.size() << '\n';
    
        // the same document always saves to the same bytes
        std::cout << (image == json_document::parse(text).save()) << '\n';
    
        // loading the image back needs no parsing, yet dumps exactly what
        // parsing the text produced
        const json_document reloaded = json_document::load(image);
        std::cout << (reloaded.root().dump() == config.root().dump()) << '\n';
    }
    
    ```

    Output:

    ```json
    316
    true
    true
    
    ```

!!! warning "Experimental"

    The image format is versioned but not yet stable, and may change in an incompatible way before it is declared
    stable. It is little-endian only (on big-endian targets, `save()` and `load()` do not exist), and tied to the
    library build that wrote it — use it to cache a document or to hand one to another process running the *same*
    build, not as a long-term storage format; keep the original JSON text if a saved document needs to be readable by
    a future library version.

The idea of a document you can read without parsing comes from zero-copy formats such as
[FlatBuffers](https://github.com/google/flatbuffers) and [YaFF](https://github.com/yandex/yaff); the check
[`load()`](../api/basic_json_document/load.md) runs follows the idea of FlatBuffers' Verifier. No code is taken from
either.

## Choosing between `json`, `ordered_json`, the SAX interface, and `json_view`

| | [`json`](../api/json.md) / [`ordered_json`](../api/ordered_json.md) | [SAX interface](parsing/sax_interface.md) | [`json_document`](../api/json_document.md) / [`json_view`](../api/json_view.md) | [`json_editable_document`](../api/json_editable_document.md) / [`json_editable_view`](../api/json_editable_view.md) |
|---|---|---|---|---|
| **Ownership** | owns every value | owns nothing; you decide what to keep, in your handler | borrows or owns the *text*; the index is always owned by the document | same as `json_document`; edits go to storage the document owns |
| **Mutability** | freely mutable | not applicable (a one-shot event stream) | read-only | [`set`](../api/basic_json_document/set.md)/[`push_back`](../api/basic_json_document/push_back.md)/[`insert`](../api/basic_json_document/insert.md)/[`erase`](../api/basic_json_document/erase.md) edit in place; the source text is never rewritten |
| **What you get** | a full tree you can read, write, and keep as long as you like | a sequence of callbacks; whatever your handler builds from them | a flat index plus, on demand, [`materialize()`](../api/basic_json_view/materialize.md)d `json`/`ordered_json` values for the parts you actually use | the same, plus [`dump()`](../api/basic_json_view/dump.md) of an edited document that keeps the member order and, with [`number_format::source`](../api/basic_json_view/number_format.md), the spelling of every untouched number |
| **Typical use** | general-purpose JSON handling: config, request/response bodies you build or modify, anything you hold onto | validating or projecting a text into your own data structure without ever holding the whole thing as JSON | large or high-volume input where you only need part of it, or need it repeatedly, and can keep the source text (or a copy) alive for as long as the document lives | a document you read, patch a few fields of, and write back — a configuration file, for instance — where the rest of it should come back exactly as it was |
| **Caching/reload** | not applicable — re-parse, or roll your own serialization | not applicable | [`save()`](../api/basic_json_document/save.md)/[`load()`](../api/basic_json_document/load.md): cache the parsed index as an image and reload it without parsing | same, saving the document's current — possibly edited — state |

<p class="nj-table-caption" markdown>Each column is one way to work with JSON in this library, and each row compares one property of them.</p>

## See also

- [`basic_json_document`](../api/basic_json_document/index.md) - the document that owns the parsed index (parse, access, images, edits)
- [`basic_json_view`](../api/basic_json_view/index.md) - the non-owning handle to a value in a document
- [`json_document`](../api/json_document.md) - and [`ordered_json_document`](../api/ordered_json_document.md) - the read-only documents
- [`json_editable_document`](../api/json_editable_document.md) - and [`ordered_json_editable_document`](../api/ordered_json_editable_document.md) - the documents that can be edited in place
- [Architecture](../home/architecture.md#node-index-of-json-views) - the layout of the node index
- [SAX interface](parsing/sax_interface.md) - event-based parsing without building a tree
- [Performance](performance.md) - benchmarks and tuning of parsing and serialization
- [Large, Streamed, and Partial Input](parsing/large_and_partial_input.md) - reading only the part of a text you need

## Version history

- Added in version 3.13.0.
