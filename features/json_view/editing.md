# Editing a document

A [`json_document`](../../api/json_document.md)/[`json_view`](../../api/json_view.md) lets you look at a parsed text
without copying it, but not change it.
[`basic_json_document<BasicJsonType, view_mode::editable>`](../../api/basic_json_document/index.md) — more
conveniently spelled [`json_editable_document`](../../api/json_editable_document.md) or
[`ordered_json_editable_document`](../../api/ordered_json_editable_document.md) — also lets you
[`set`](../../api/basic_json_document/set.md) a value, [`push_back`](../../api/basic_json_document/push_back.md) onto
or [`insert`](../../api/basic_json_document/insert.md) into an array, and
[`erase`](../../api/basic_json_document/erase.md) an object member or an array element, still without ever building a
`basic_json` tree for parts you do not touch.

The [mode](../../api/view_mode.md) defaults to `#!cpp view_mode::read_only`, so
`json_document`/`ordered_json_document` are unaffected — they carry none of the bookkeeping edits need, and calling
`set`/`push_back`/`insert`/`erase` on one is a compile error, not a runtime one.

## Why: editing without reformatting

A price like `#!cpp 19.90` is exactly the kind of value that makes editing a `json` or `ordered_json` value in place
lossy. Say you parse a configuration file, patch one field, and write it back:

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

An editable document keeps both. [`dump()`](../../api/basic_json_view/dump.md) of an edited document writes members in
document order — a member [`set`](../../api/basic_json_document/set.md) added goes at the end, exactly where it was
inserted, and an [`erase`](../../api/basic_json_document/erase.md)d member simply leaves a gap: everything around it
keeps its place — and [`number_format::source`](../../api/basic_json_view/number_format.md) keeps the exact spelling
of every number an edit did not itself touch; a number an edit *did* touch is written the way
[`BasicJsonType::dump()`](../../api/basic_json/dump.md) would write it, since there is no source spelling for a brand
new value. See [Writing a view back](reading.md#writing-a-view-back).

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

## What stays valid, and what an edit costs

The source text itself is **never written**, and the parsed index never moves — a value keeps the node it was
parsed into for as long as it is not itself replaced. So every [view](../../api/basic_json_view/index.md) taken before
an edit, including a previously obtained [`root()`](../../api/basic_json_document/root.md), stays valid and, if it
still refers to the edited value, sees the edit; a view of a value a later edit drops or replaces just keeps showing
what it last held. New values go to storage the document allocates and owns on demand. The one thing an edit does
invalidate is the **iterators** taken over an edited array or object: the first time an element is added to it,
inserted into it, erased from it, or replaced by a value that spans a different number of nodes, its elements move
from the parsed, fixed layout to a growable block of links so that
[`push_back`](../../api/basic_json_document/push_back.md) can later grow it in amortized constant time — existing
elements are not touched, but an iterator that was walking the old layout no longer matches. A string obtained with
[`get_string()`](../../api/basic_json_view/get_string.md) is unaffected either way and stays valid across further
edits. See [`basic_json_document`'s Edits](../../api/basic_json_document/index.md#edits) for the details, and
[`set`'s Exception safety](../../api/basic_json_document/set.md#exception-safety) for what an edit guarantees if it
throws (the *basic* guarantee, not the strong one `dump()` and the read-only functions provide). How edits are kept in
the index is described in the [architecture overview](../../home/architecture.md#node-index-of-json-views).

Step through the edits of a small document (the node fields follow the
[architecture overview](../../home/architecture.md#node-index-of-json-views)):

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

## See also

- [Zero-copy JSON views](index.md) - overview
- [`json_editable_document`](../../api/json_editable_document.md) - and [`ordered_json_editable_document`](../../api/ordered_json_editable_document.md) - the documents that can be edited in place
- [`basic_json_document`'s Edits](../../api/basic_json_document/index.md#edits) - the rules of edits in detail
- [Differences from `basic_json`](differences.md#exception-context) - source positions after edits

## Version history

- Added in version 3.13.0.
