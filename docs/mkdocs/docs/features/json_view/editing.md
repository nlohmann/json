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
    --8<-- "examples/json_editable_document.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/json_editable_document.output"
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
--8<-- "images/json_view_edit_0.svg"
</div>
<figcaption>Step 1 of 5. After parsing: nine nodes in the parsed index, no owned storage yet.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set an existing member">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_1.svg"
</div>
<figcaption>Step 2 of 5. <code>doc.set(doc.root(), "port", 6380)</code> overwrites the node of the integer in place; no member is added or removed, so the object keeps its parsed layout.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="erase an array element">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_2.svg"
</div>
<figcaption>Step 3 of 5. <code>doc.erase(doc.root()["tags"], 0)</code>: the array is edited for the first time, so its elements move to a block of links in owned storage. The node of <code>"eu"</code> stays in the index, but nothing refers to it any more; iterators over the array taken before are invalid.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="push_back onto the array">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_3.svg"
</div>
<figcaption>Step 4 of 5. <code>doc.push_back(doc.root()["tags"], "new")</code>: the new string gets its own node, its text goes to the buffer of edited text, and a link to it is appended to the block of the array.</figcaption>
</figure>
<figure class="nj-jsonview-step" data-label="set a new member">
<div class="nj-jsonview-scroll">
--8<-- "images/json_view_edit_4.svg"
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
