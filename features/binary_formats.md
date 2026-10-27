# Binary Formats

Though JSON is a ubiquitous data format, it is not a very compact format suitable for data exchange, for instance, over
a network. Hence, the library supports

- [BJData](bjdata.md) (Binary JData),
- [BON8](bon8.md) (Binary Object Notation 8),
- [BSON](bson.md) (Binary JSON),
- [CBOR](cbor.md) (Concise Binary Object Representation),
- [MessagePack](messagepack.md), and
- [UBJSON](ubjson.md) (Universal Binary JSON)

to efficiently encode JSON values to byte vectors and to decode such vectors.

## Comparison

### Completeness

| Format      | Serialization                                 | Deserialization                                                       |
|-------------|-----------------------------------------------|-----------------------------------------------------------------------|
| BJData      | complete                                      | incomplete: no column-major ND-arrays, no Draft 4 SoA/extension types |
| BON8        | incomplete: no unsigned integers above int64  | complete                                                              |
| BSON        | incomplete: top-level value must be an object | incomplete, but all JSON types are supported                          |
| CBOR        | complete                                      | incomplete, but all JSON types are supported                          |
| MessagePack | complete                                      | incomplete, but all JSON types are supported                          |
| UBJSON      | complete                                      | complete                                                              |

### Binary values

| Format      | Binary values            | Binary subtypes |
|-------------|--------------------------|-----------------|
| BJData      | supported (Draft 3 only) | not supported   |
| BON8        | not supported            | not supported   |
| BSON        | supported                | supported       |
| CBOR        | supported                | supported       |
| MessagePack | supported                | supported       |
| UBJSON      | not supported            | not supported   |

See [binary values](../binary_values.md) for more information.

### Sizes

| Format             | canada.json | twitter.json | citm_catalog.json | jeopardy.json |
|--------------------|-------------|--------------|-------------------|---------------|
| BJData             | 53.2 %      | 91.1 %       | 78.1 %            | 96.6 %        |
| BJData (size)      | 58.6 %      | 92.1 %       | 86.7 %            | 97.4 %        |
| BJData (size+type) | 58.6 %      | 92.1 %       | 86.5 %            | 97.4 %        |
| BON8               | **50.5 %**  | **83.8 %**   | **63.5 %**        | **87.5 %**    |
| BSON               | 85.8 %      | 95.2 %       | 95.8 %            | 106.7 %       |
| CBOR               | **50.5 %**  | 86.3 %       | 68.4 %            | 88.0 %        |
| MessagePack        | **50.5 %**  | 86.0 %       | 68.5 %            | 87.9 %        |
| UBJSON             | 53.2 %      | 91.3 %       | 78.2 %            | 96.6 %        |
| UBJSON (size)      | 58.6 %      | 92.3 %       | 86.8 %            | 97.4 %        |
| UBJSON (size+type) | 55.9 %      | 92.3 %       | 85.0 %            | 95.0 %        |

<p class="nj-table-caption" markdown>Size of each test file in each format, in percent of the minified JSON value; the smallest size per file is printed in bold. The (size) and (size+type) rows are written with the `use_size` and `use_type` options of [`to_bjdata`](../../api/basic_json/to_bjdata.md) and [`to_ubjson`](../../api/basic_json/to_ubjson.md).</p>

<div class="nj-charts-grid-wrap" markdown>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--sizes" viewBox="0 0 340 220" role="img" aria-labelledby="nj-charts-bs-canada nj-charts-bs-canada-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-bs-canada">Size of canada.json in each binary format relative to minified J&#8203;SON</title>
<desc id="nj-charts-bs-canada-d">B&#8203;JData 53.2 %; B&#8203;ON8 50.5 %; B&#8203;SON 85.8 %; C&#8203;BOR 50.5 %; MessagePack 50.5 %; U&#8203;BJSON 53.2 %. Smallest: B&#8203;ON8 and C&#8203;BOR and MessagePack.</desc>
<text class="nj-charts-panel" x="8" y="18">canada.json</text>
<line class="nj-charts-grid" x1="104" y1="40" x2="104" y2="196"/>
<text class="nj-charts-tick" x="104" y="211">0 %</text>
<line class="nj-charts-grid" x1="186.727" y1="40" x2="186.727" y2="196"/>
<text class="nj-charts-tick" x="186.727" y="211">50 %</text>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="58.5">B&#8203;JData</text>
<path class="nj-charts-c1 nj-charts-dim" d="M104 46 H188.022 Q192.022 46 192.022 50 V58 Q192.022 62 188.022 62 H104 Z"><title>canada.json, B&#8203;JData: 53.2 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="84.5">B&#8203;ON8</text>
<path class="nj-charts-c2" d="M104 72 H183.555 Q187.555 72 187.555 76 V84 Q187.555 88 183.555 88 H104 Z"><title>canada.json, B&#8203;ON8: 50.5 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="110.5">B&#8203;SON</text>
<path class="nj-charts-c3 nj-charts-dim" d="M104 98 H241.96 Q245.96 98 245.96 102 V110 Q245.96 114 241.96 114 H104 Z"><title>canada.json, B&#8203;SON: 85.8 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="136.5">C&#8203;BOR</text>
<path class="nj-charts-c4" d="M104 124 H183.555 Q187.555 124 187.555 128 V136 Q187.555 140 183.555 140 H104 Z"><title>canada.json, C&#8203;BOR: 50.5 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="162.5">MessagePack</text>
<path class="nj-charts-c5" d="M104 150 H183.555 Q187.555 150 187.555 154 V162 Q187.555 166 183.555 166 H104 Z"><title>canada.json, MessagePack: 50.5 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="188.5">U&#8203;BJSON</text>
<path class="nj-charts-c6 nj-charts-dim" d="M104 176 H188.022 Q192.022 176 192.022 180 V188 Q192.022 192 188.022 192 H104 Z"><title>canada.json, U&#8203;BJSON: 53.2 % of minified J&#8203;SON</title></path>
<line class="nj-charts-ref" x1="269.455" y1="36" x2="269.455" y2="196"/>
<text class="nj-charts-tick nj-charts-tick--r" x="271.455" y="32">minified J&#8203;SON = 100 %</text>
<text class="nj-charts-tick" x="269.455" y="211">100 %</text>
<text class="nj-charts-val" x="197.022" y="58.5">53.2 %</text>
<text class="nj-charts-val nj-charts-best" x="192.555" y="84.5">50.5 %</text>
<text class="nj-charts-val" x="250.96" y="110.5">85.8 %</text>
<text class="nj-charts-val nj-charts-best" x="192.555" y="136.5">50.5 %</text>
<text class="nj-charts-val nj-charts-best" x="192.555" y="162.5">50.5 %</text>
<text class="nj-charts-val" x="197.022" y="188.5">53.2 %</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--sizes" viewBox="0 0 340 220" role="img" aria-labelledby="nj-charts-bs-twitter nj-charts-bs-twitter-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-bs-twitter">Size of twitter.json in each binary format relative to minified J&#8203;SON</title>
<desc id="nj-charts-bs-twitter-d">B&#8203;JData 91.1 %; B&#8203;ON8 83.8 %; B&#8203;SON 95.2 %; C&#8203;BOR 86.3 %; MessagePack 86 %; U&#8203;BJSON 91.3 %. Smallest: B&#8203;ON8.</desc>
<text class="nj-charts-panel" x="8" y="18">twitter.json</text>
<line class="nj-charts-grid" x1="104" y1="40" x2="104" y2="196"/>
<text class="nj-charts-tick" x="104" y="211">0 %</text>
<line class="nj-charts-grid" x1="186.727" y1="40" x2="186.727" y2="196"/>
<text class="nj-charts-tick" x="186.727" y="211">50 %</text>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="58.5">B&#8203;JData</text>
<path class="nj-charts-c1 nj-charts-dim" d="M104 46 H250.729 Q254.729 46 254.729 50 V58 Q254.729 62 250.729 62 H104 Z"><title>twitter.json, B&#8203;JData: 91.1 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="84.5">B&#8203;ON8</text>
<path class="nj-charts-c2" d="M104 72 H238.651 Q242.651 72 242.651 76 V84 Q242.651 88 238.651 88 H104 Z"><title>twitter.json, B&#8203;ON8: 83.8 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="110.5">B&#8203;SON</text>
<path class="nj-charts-c3 nj-charts-dim" d="M104 98 H257.513 Q261.513 98 261.513 102 V110 Q261.513 114 257.513 114 H104 Z"><title>twitter.json, B&#8203;SON: 95.2 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="136.5">C&#8203;BOR</text>
<path class="nj-charts-c4 nj-charts-dim" d="M104 124 H242.787 Q246.787 124 246.787 128 V136 Q246.787 140 242.787 140 H104 Z"><title>twitter.json, C&#8203;BOR: 86.3 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="162.5">MessagePack</text>
<path class="nj-charts-c5 nj-charts-dim" d="M104 150 H242.291 Q246.291 150 246.291 154 V162 Q246.291 166 242.291 166 H104 Z"><title>twitter.json, MessagePack: 86 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="188.5">U&#8203;BJSON</text>
<path class="nj-charts-c6 nj-charts-dim" d="M104 176 H251.06 Q255.06 176 255.06 180 V188 Q255.06 192 251.06 192 H104 Z"><title>twitter.json, U&#8203;BJSON: 91.3 % of minified J&#8203;SON</title></path>
<line class="nj-charts-ref" x1="269.455" y1="36" x2="269.455" y2="196"/>
<text class="nj-charts-tick nj-charts-tick--r" x="271.455" y="32">minified J&#8203;SON = 100 %</text>
<text class="nj-charts-tick" x="269.455" y="211">100 %</text>
<text class="nj-charts-val" x="259.729" y="58.5">91.1 %</text>
<text class="nj-charts-val nj-charts-best" x="247.651" y="84.5">83.8 %</text>
<text class="nj-charts-val" x="266.513" y="110.5">95.2 %</text>
<text class="nj-charts-val" x="251.787" y="136.5">86.3 %</text>
<text class="nj-charts-val" x="251.291" y="162.5">86.0 %</text>
<text class="nj-charts-val" x="260.06" y="188.5">91.3 %</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--sizes" viewBox="0 0 340 220" role="img" aria-labelledby="nj-charts-bs-citm_catalog nj-charts-bs-citm_catalog-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-bs-citm_catalog">Size of citm_catalog.json in each binary format relative to minified J&#8203;SON</title>
<desc id="nj-charts-bs-citm_catalog-d">B&#8203;JData 78.1 %; B&#8203;ON8 63.5 %; B&#8203;SON 95.8 %; C&#8203;BOR 68.4 %; MessagePack 68.5 %; U&#8203;BJSON 78.2 %. Smallest: B&#8203;ON8.</desc>
<text class="nj-charts-panel" x="8" y="18">citm_catalog.json</text>
<line class="nj-charts-grid" x1="104" y1="40" x2="104" y2="196"/>
<text class="nj-charts-tick" x="104" y="211">0 %</text>
<line class="nj-charts-grid" x1="186.727" y1="40" x2="186.727" y2="196"/>
<text class="nj-charts-tick" x="186.727" y="211">50 %</text>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="58.5">B&#8203;JData</text>
<path class="nj-charts-c1 nj-charts-dim" d="M104 46 H229.22 Q233.22 46 233.22 50 V58 Q233.22 62 229.22 62 H104 Z"><title>citm_catalog.json, B&#8203;JData: 78.1 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="84.5">B&#8203;ON8</text>
<path class="nj-charts-c2" d="M104 72 H205.064 Q209.064 72 209.064 76 V84 Q209.064 88 205.064 88 H104 Z"><title>citm_catalog.json, B&#8203;ON8: 63.5 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="110.5">B&#8203;SON</text>
<path class="nj-charts-c3 nj-charts-dim" d="M104 98 H258.505 Q262.505 98 262.505 102 V110 Q262.505 114 258.505 114 H104 Z"><title>citm_catalog.json, B&#8203;SON: 95.8 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="136.5">C&#8203;BOR</text>
<path class="nj-charts-c4 nj-charts-dim" d="M104 124 H213.171 Q217.171 124 217.171 128 V136 Q217.171 140 213.171 140 H104 Z"><title>citm_catalog.json, C&#8203;BOR: 68.4 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="162.5">MessagePack</text>
<path class="nj-charts-c5 nj-charts-dim" d="M104 150 H213.336 Q217.336 150 217.336 154 V162 Q217.336 166 213.336 166 H104 Z"><title>citm_catalog.json, MessagePack: 68.5 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="188.5">U&#8203;BJSON</text>
<path class="nj-charts-c6 nj-charts-dim" d="M104 176 H229.385 Q233.385 176 233.385 180 V188 Q233.385 192 229.385 192 H104 Z"><title>citm_catalog.json, U&#8203;BJSON: 78.2 % of minified J&#8203;SON</title></path>
<line class="nj-charts-ref" x1="269.455" y1="36" x2="269.455" y2="196"/>
<text class="nj-charts-tick nj-charts-tick--r" x="271.455" y="32">minified J&#8203;SON = 100 %</text>
<text class="nj-charts-tick" x="269.455" y="211">100 %</text>
<text class="nj-charts-val" x="238.22" y="58.5">78.1 %</text>
<text class="nj-charts-val nj-charts-best" x="214.064" y="84.5">63.5 %</text>
<text class="nj-charts-val" x="267.505" y="110.5">95.8 %</text>
<text class="nj-charts-val" x="222.171" y="136.5">68.4 %</text>
<text class="nj-charts-val" x="222.336" y="162.5">68.5 %</text>
<text class="nj-charts-val" x="238.385" y="188.5">78.2 %</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--sizes" viewBox="0 0 340 220" role="img" aria-labelledby="nj-charts-bs-jeopardy nj-charts-bs-jeopardy-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-charts-bs-jeopardy">Size of jeopardy.json in each binary format relative to minified J&#8203;SON</title>
<desc id="nj-charts-bs-jeopardy-d">B&#8203;JData 96.6 %; B&#8203;ON8 87.5 %; B&#8203;SON 106.7 %; C&#8203;BOR 88 %; MessagePack 87.9 %; U&#8203;BJSON 96.6 %. Smallest: B&#8203;ON8.</desc>
<text class="nj-charts-panel" x="8" y="18">jeopardy.json</text>
<line class="nj-charts-grid" x1="104" y1="40" x2="104" y2="196"/>
<text class="nj-charts-tick" x="104" y="211">0 %</text>
<line class="nj-charts-grid" x1="186.727" y1="40" x2="186.727" y2="196"/>
<text class="nj-charts-tick" x="186.727" y="211">50 %</text>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="58.5">B&#8203;JData</text>
<path class="nj-charts-c1 nj-charts-dim" d="M104 46 H259.829 Q263.829 46 263.829 50 V58 Q263.829 62 259.829 62 H104 Z"><title>jeopardy.json, B&#8203;JData: 96.6 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt nj-charts-best" x="96" y="84.5">B&#8203;ON8</text>
<path class="nj-charts-c2" d="M104 72 H244.773 Q248.773 72 248.773 76 V84 Q248.773 88 244.773 88 H104 Z"><title>jeopardy.json, B&#8203;ON8: 87.5 % of minified J&#8203;SON (smallest)</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="110.5">B&#8203;SON</text>
<path class="nj-charts-c3 nj-charts-dim" d="M104 98 H276.54 Q280.54 98 280.54 102 V110 Q280.54 114 276.54 114 H104 Z"><title>jeopardy.json, B&#8203;SON: 106.7 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="136.5">C&#8203;BOR</text>
<path class="nj-charts-c4 nj-charts-dim" d="M104 124 H245.6 Q249.6 124 249.6 128 V136 Q249.6 140 245.6 140 H104 Z"><title>jeopardy.json, C&#8203;BOR: 88 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="162.5">MessagePack</text>
<path class="nj-charts-c5 nj-charts-dim" d="M104 150 H245.435 Q249.435 150 249.435 154 V162 Q249.435 166 245.435 166 H104 Z"><title>jeopardy.json, MessagePack: 87.9 % of minified J&#8203;SON</title></path>
<text class="nj-charts-rowlabel nj-charts-fmt" x="96" y="188.5">U&#8203;BJSON</text>
<path class="nj-charts-c6 nj-charts-dim" d="M104 176 H259.829 Q263.829 176 263.829 180 V188 Q263.829 192 259.829 192 H104 Z"><title>jeopardy.json, U&#8203;BJSON: 96.6 % of minified J&#8203;SON</title></path>
<line class="nj-charts-ref" x1="269.455" y1="36" x2="269.455" y2="196"/>
<text class="nj-charts-tick nj-charts-tick--r" x="271.455" y="32">minified J&#8203;SON = 100 %</text>
<text class="nj-charts-tick" x="269.455" y="211">100 %</text>
<text class="nj-charts-val" x="268.829" y="58.5">96.6 %</text>
<text class="nj-charts-val nj-charts-best" x="253.773" y="84.5">87.5 %</text>
<text class="nj-charts-val" x="285.54" y="110.5">106.7 %</text>
<text class="nj-charts-val" x="254.6" y="136.5">88.0 %</text>
<text class="nj-charts-val" x="254.435" y="162.5">87.9 %</text>
<text class="nj-charts-val" x="268.829" y="188.5">96.6 %</text>
</svg>

</div>
</div>
<p class="nj-charts-caption" markdown>The table above as charts: size per base format relative to minified JSON (vertical line at
100 %); the smallest format per file is drawn in a stronger colour than the others. The size and size+type variants of BJData and UBJSON are
omitted here; see the table.</p>

## See also

- [`cbor_tag_handler_t`](../../api/basic_json/cbor_tag_handler_t.md) - how CBOR tags are handled when parsing
- [`JSON_STRICT_BINARY_UTF8`](../../api/macros/json_strict_binary_utf8.md) - reject ill-formed UTF-8 in strings
- [Binary values](../binary_values.md) - binary values and subtypes
- [`to_cbor`](../../api/basic_json/to_cbor.md) - / [`from_cbor`](../../api/basic_json/from_cbor.md), [`to_msgpack`](../../api/basic_json/to_msgpack.md) / [`from_msgpack`](../../api/basic_json/from_msgpack.md), [`to_bson`](../../api/basic_json/to_bson.md) / [`from_bson`](../../api/basic_json/from_bson.md), [`to_ubjson`](../../api/basic_json/to_ubjson.md) / [`from_ubjson`](../../api/basic_json/from_ubjson.md), [`to_bjdata`](../../api/basic_json/to_bjdata.md) / [`from_bjdata`](../../api/basic_json/from_bjdata.md), [`to_bon8`](../../api/basic_json/to_bon8.md) / [`from_bon8`](../../api/basic_json/from_bon8.md) - the conversion functions
- [Parsing untrusted input](../parsing/untrusted_input.md) - harden an application that parses untrusted binary data
- [SAX interface](../parsing/sax_interface.md) - decode binary formats without building a value

