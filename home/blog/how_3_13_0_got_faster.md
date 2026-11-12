# How nlohmann/json 3.13.0 got 3× faster

<p class="nj-byline"><a href="https://github.com/nlohmann">Niels Lohmann</a> · <time datetime="2026-10-28">October 28,
2026</time></p>

<!-- Before publishing: set the date to the release date, and measure every number of this post again with the
     v3.13.0 tag (Appendix G describes the setup; tests/benchmarks/json_view/others/README.md has the commands of the
     comparison), including the line counts in "The price". The numbers below are from develop 7fc8312c64 with the
     open pull requests #6029, #6031, #6033 and #6039 merged (local branch local/all-prs-1107 at fcae242ac8, plus
     #6039 uncommitted), measured 11-07: suite, timeline (the commits after 11-03 and 3.13.0; the older points are from
     10-27 and 11-03), compile times (5 rounds), the stream gap, and the comparison on the Mac and on x86-64.
     Appendix D and the Intel MacBook Pro column of Appendix B are from 11-03 (the MacBook was not reachable), and so
     is the check with GCC 16 and Clang 23 on the Mac in "Results on x86-64". The Rust times are from 10-29 (Mac) and
     11-03 (x86-64), the x86-64 conformance run from 10-30. Once #6031 is merged, remove it from PENDING in
     scripts/figures/perf_blog.py. Merge tests/benchmarks/json_view/others before publishing (the links 404). -->

Since 2016, the [README](https://github.com/nlohmann/json#readme) of this library has said this about speed:

> There are certainly faster JSON libraries out there. However, if your goal is to speed up your development by adding
> JSON support with a single header, then this library is the way to go.

That sentence is still true, but the gap is a lot smaller now. Swap the 3.12.0 header for the 3.13.0 one, recompile, and
the 182 benchmarks of the library's own suite run 3.3× as fast on an Apple M1 Max (geometric mean; 3.1× on an Intel
MacBook Pro from 2016). Not a line of your code changes. Parsing typical documents got 3.5–5.1× as fast, and writing
them 2.9–6.6×. The new version also adds [`json_document`](../../features/json_view/index.md), a second way to hold a parsed
document, which competes with the fastest C++ and Rust JSON libraries; [How it compares](#how-it-compares) has the
numbers, including where it loses. The price is compile time: two small example programs take 36–68% longer to compile.
A precompiled header or a C++20 module wins back most or all of that in debug builds, and 41% to all of it in
optimized builds ([The price](#the-price)).

This post is about *how*. Hardly any of the techniques are new: we borrowed them from
[simdjson](https://github.com/simdjson/simdjson), [yyjson](https://github.com/ibireme/yyjson),
[fast_float](https://github.com/fastfloat/fast_float), [Żmij](https://github.com/vitaut/zmij),
[serde_json](https://github.com/serde-rs/json), [Glaze](https://github.com/stephenberry/glaze),
[SQLite](https://sqlite.org), [Boost.JSON](https://github.com/boostorg/json), [gnulib](https://www.gnu.org/software/gnulib/),
or a textbook, and we name the source at
each step. What is worth writing about is the *combination*, and the conditions it had to work under. It is a
header-only C++11 library whose 3.x API has been stable for almost nine years, and whose value type is a template over
its string, number, object, array, and allocator types. Input comes from strings, streams, `FILE*`, iterator pairs, wide
strings, and user-defined adapters. Output had to stay the same byte for byte, and error messages had to keep pointing
at the same byte. The few deliberate changes of output are listed in [Appendix F](#f-behavior-changes).

Every number comes from a benchmark we ran for this post or from the pull request that made the change. The
[appendix](#appendix) describes the test files and the setup, has the full tables behind every chart, and lists the pull
requests behind each theme.

Fast paths are where bugs hide: they run only for some inputs, so a mistake in one can go unnoticed until the right
input comes along. So every fast path was tested against the slow path it replaces, on millions of generated and fuzzed
inputs. Both had to return the same value, or fail with the same error message at the same byte. [Appendix
J](#j-validation) lists the checks.

## The short version

The test files are the three of Milo Yip's [nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark) that
JSON libraries have been measured with for a decade, `twitter.json` (strings, much of it Japanese), `citm_catalog.json`
(many small objects, indented) and `canada.json` (floating-point numbers), plus the 56 MB `jeopardy.json`. [Appendix
A](#a-test-files) says what makes each of them hard.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog" viewBox="0 0 560 604" role="img" aria-labelledby="nj-blog-overview nj-blog-overview-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-overview">Speedup of 3.13.0 over 3.12.0 per workload, Apple M1 Max, Apple clang</title>
<desc id="nj-blog-overview-d">Horizontal bars of the speedup, more is better. twitter.json 3.5x; citm_catalog.json 5.1x; canada.json 4.1x; canada.json, indented 7.4x; citm, ordered_json 8.2x; twitter, std::ifstream 2.5x; citm, FILE* 15x; citm, accept() 14x; dump() twitter 6.6x; dump() canada 2.9x; dump(4) citm 4.6x; to_cbor() twitter 4.4x; twitter, memory 3.5x; twitter, FILE* 9.2x; diff() canada 10x; iterate canada 1.96x; copy + destroy citm 1.11x; == citm 1.01x.</desc>
<text class="nj-charts-panel" x="8" y="20">Parsing</text>
<text class="nj-charts-panel" x="8" y="244">Writing</text>
<text class="nj-charts-panel" x="8" y="372">Reading C&#8203;BOR</text>
<text class="nj-charts-panel" x="8" y="452">Values</text>
<line class="nj-charts-grid" x1="210.625" y1="8" x2="210.625" y2="560"/>
<text class="nj-charts-tick" x="210.625" y="576">1&#215;</text>
<line class="nj-charts-grid" x1="231.25" y1="8" x2="231.25" y2="560"/>
<text class="nj-charts-tick" x="231.25" y="576">2&#215;</text>
<line class="nj-charts-grid" x1="251.875" y1="8" x2="251.875" y2="560"/>
<text class="nj-charts-tick" x="251.875" y="576">3&#215;</text>
<line class="nj-charts-grid" x1="272.5" y1="8" x2="272.5" y2="560"/>
<text class="nj-charts-tick" x="272.5" y="576">4&#215;</text>
<line class="nj-charts-grid" x1="293.125" y1="8" x2="293.125" y2="560"/>
<text class="nj-charts-tick" x="293.125" y="576">5&#215;</text>
<line class="nj-charts-grid" x1="313.75" y1="8" x2="313.75" y2="560"/>
<text class="nj-charts-tick" x="313.75" y="576">6&#215;</text>
<line class="nj-charts-grid" x1="334.375" y1="8" x2="334.375" y2="560"/>
<text class="nj-charts-tick" x="334.375" y="576">7&#215;</text>
<line class="nj-charts-grid" x1="355" y1="8" x2="355" y2="560"/>
<text class="nj-charts-tick" x="355" y="576">8&#215;</text>
<line class="nj-charts-grid" x1="375.625" y1="8" x2="375.625" y2="560"/>
<text class="nj-charts-tick" x="375.625" y="576">9&#215;</text>
<line class="nj-charts-grid" x1="396.25" y1="8" x2="396.25" y2="560"/>
<text class="nj-charts-tick" x="396.25" y="576">10&#215;</text>
<line class="nj-charts-grid" x1="416.875" y1="8" x2="416.875" y2="560"/>
<text class="nj-charts-tick" x="416.875" y="576">11&#215;</text>
<line class="nj-charts-grid" x1="437.5" y1="8" x2="437.5" y2="560"/>
<text class="nj-charts-tick" x="437.5" y="576">12&#215;</text>
<line class="nj-charts-grid" x1="458.125" y1="8" x2="458.125" y2="560"/>
<text class="nj-charts-tick" x="458.125" y="576">13&#215;</text>
<line class="nj-charts-grid" x1="478.75" y1="8" x2="478.75" y2="560"/>
<text class="nj-charts-tick" x="478.75" y="576">14&#215;</text>
<line class="nj-charts-grid" x1="499.375" y1="8" x2="499.375" y2="560"/>
<text class="nj-charts-tick" x="499.375" y="576">15&#215;</text>
<line class="nj-charts-grid" x1="520" y1="8" x2="520" y2="560"/>
<text class="nj-charts-tick" x="520" y="576">16&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="42" text-anchor="end">twitter.json</text>
<path class="nj-charts-c1" d="M190 30 H257.981 Q261.981 30 261.981 34 V41 Q261.981 45 257.981 45 H190 Z"><title>twitter.json: 3.5&#215;</title></path>
<text class="nj-charts-val" x="266.981" y="42">3.5&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="66" text-anchor="end">citm_catalog.json</text>
<path class="nj-charts-c1" d="M190 54 H291.394 Q295.394 54 295.394 58 V65 Q295.394 69 291.394 69 H190 Z"><title>citm_catalog.json: 5.1&#215;</title></path>
<text class="nj-charts-val" x="300.394" y="66">5.1&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="90" text-anchor="end">canada.json</text>
<path class="nj-charts-c1" d="M190 78 H270.15 Q274.15 78 274.15 82 V89 Q274.15 93 270.15 93 H190 Z"><title>canada.json: 4.1&#215;</title></path>
<text class="nj-charts-val" x="279.15" y="90">4.1&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="114" text-anchor="end">canada.json, indented</text>
<path class="nj-charts-c1" d="M190 102 H338.831 Q342.831 102 342.831 106 V113 Q342.831 117 338.831 117 H190 Z"><title>canada.json, indented: 7.4&#215;</title></path>
<text class="nj-charts-val" x="347.831" y="114">7.4&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="138" text-anchor="end">citm, ordered_json</text>
<path class="nj-charts-c1" d="M190 126 H354.712 Q358.712 126 358.712 130 V137 Q358.712 141 354.712 141 H190 Z"><title>citm, ordered_json: 8.2&#215;</title></path>
<text class="nj-charts-val" x="363.712" y="138">8.2&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="162" text-anchor="end">twitter, std::ifstream</text>
<path class="nj-charts-c1" d="M190 150 H236.738 Q240.738 150 240.738 154 V161 Q240.738 165 236.738 165 H190 Z"><title>twitter, std::ifstream: 2.5&#215;</title></path>
<text class="nj-charts-val" x="245.738" y="162">2.5&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="186" text-anchor="end">citm, FILE*</text>
<path class="nj-charts-c1" d="M190 174 H494.137 Q498.137 174 498.137 178 V185 Q498.137 189 494.137 189 H190 Z"><title>citm, FILE*: 15&#215;</title></path>
<text class="nj-charts-val" x="503.137" y="186">15&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="210" text-anchor="end">citm, accept()</text>
<path class="nj-charts-c1" d="M190 198 H467.738 Q471.738 198 471.738 202 V209 Q471.738 213 467.738 213 H190 Z"><title>citm, accept(): 14&#215;</title></path>
<text class="nj-charts-val" x="476.738" y="210">14&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="266" text-anchor="end">dump() twitter</text>
<path class="nj-charts-c1" d="M190 254 H322.125 Q326.125 254 326.125 258 V265 Q326.125 269 322.125 269 H190 Z"><title>dump() twitter: 6.6&#215;</title></path>
<text class="nj-charts-val" x="331.125" y="266">6.6&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="290" text-anchor="end">dump() canada</text>
<path class="nj-charts-c1" d="M190 278 H245.812 Q249.812 278 249.812 282 V289 Q249.812 293 245.812 293 H190 Z"><title>dump() canada: 2.9&#215;</title></path>
<text class="nj-charts-val" x="254.812" y="290">2.9&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="314" text-anchor="end">dump(4) citm</text>
<path class="nj-charts-c1" d="M190 302 H281.288 Q285.288 302 285.288 306 V313 Q285.288 317 281.288 317 H190 Z"><title>dump(4) citm: 4.6&#215;</title></path>
<text class="nj-charts-val" x="290.288" y="314">4.6&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="338" text-anchor="end">to_cbor() twitter</text>
<path class="nj-charts-c1" d="M190 326 H276.956 Q280.956 326 280.956 330 V337 Q280.956 341 276.956 341 H190 Z"><title>to_cbor() twitter: 4.4&#215;</title></path>
<text class="nj-charts-val" x="285.956" y="338">4.4&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="394" text-anchor="end">twitter, memory</text>
<path class="nj-charts-c1" d="M190 382 H258.6 Q262.6 382 262.6 386 V393 Q262.6 397 258.6 397 H190 Z"><title>twitter, memory: 3.5&#215;</title></path>
<text class="nj-charts-val" x="267.6" y="394">3.5&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="418" text-anchor="end">twitter, FILE*</text>
<path class="nj-charts-c1" d="M190 406 H376.369 Q380.369 406 380.369 410 V417 Q380.369 421 376.369 421 H190 Z"><title>twitter, FILE*: 9.2&#215;</title></path>
<text class="nj-charts-val" x="385.369" y="418">9.2&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="474" text-anchor="end">diff() canada</text>
<path class="nj-charts-c1" d="M190 462 H401.325 Q405.325 462 405.325 466 V473 Q405.325 477 401.325 477 H190 Z"><title>diff() canada: 10&#215;</title></path>
<text class="nj-charts-val" x="410.325" y="474">10&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="498" text-anchor="end">iterate canada</text>
<path class="nj-charts-c1" d="M190 486 H226.425 Q230.425 486 230.425 490 V497 Q230.425 501 226.425 501 H190 Z"><title>iterate canada: 1.96&#215;</title></path>
<text class="nj-charts-val" x="235.425" y="498">1.96&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="522" text-anchor="end">copy + destroy citm</text>
<path class="nj-charts-c1" d="M190 510 H208.894 Q212.894 510 212.894 514 V521 Q212.894 525 208.894 525 H190 Z"><title>copy + destroy citm: 1.11&#215;</title></path>
<text class="nj-charts-val" x="217.894" y="522">1.11&#215;</text>
<text class="nj-charts-rowlabel nj-charts-tick--r" x="182" y="546" text-anchor="end">== citm</text>
<path class="nj-charts-c1" d="M190 534 H206.831 Q210.831 534 210.831 538 V545 Q210.831 549 206.831 549 H190 Z"><title>== citm: 1.01&#215;</title></path>
<text class="nj-charts-val" x="215.831" y="546">1.01&#215;</text>
<line class="nj-charts-ref" x1="210.625" y1="8" x2="210.625" y2="560"/>
<line class="nj-charts-zero" x1="190" y1="8" x2="190" y2="560"/>
<text class="nj-charts-tick" x="355" y="594">speedup over 3.12.0 (3.12.0 = 1&#215;), more is better</text>
</svg>

</div>

<p class="nj-caption" markdown>Speedup of 3.13.0 over 3.12.0 for a selection of workloads: the old time divided by the
new one, Google Benchmark suite on an Apple M1 Max, median of 12 runs. More is better; the vertical line at 1× is
3.12.0. The times are in [Appendix B](#b-3120-against-3130).</p>

The rows above are chosen to show the range. All 182 benchmarks of the suite:

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog" viewBox="0 0 560 250" role="img" aria-labelledby="nj-blog-dist nj-blog-dist-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-dist">Speedup of 3.13.0 over 3.12.0 for all 182 benchmarks of the suite</title>
<desc id="nj-blog-dist-d">Bars counting the benchmarks per speedup range: below 1x: 2; 1 to 1.5x: 21; 1.5 to 2x: 18; 2 to 3x: 52; 3 to 5x: 48; 5 to 10x: 31; 10x or more: 10. Median 2.9x, geometric mean 3.3x.</desc>
<line class="nj-charts-grid" x1="52" y1="196" x2="548" y2="196"/>
<text class="nj-charts-tick nj-charts-tick--r" x="46" y="200">0</text>
<line class="nj-charts-grid" x1="52" y1="136" x2="548" y2="136"/>
<text class="nj-charts-tick nj-charts-tick--r" x="46" y="140">20</text>
<line class="nj-charts-grid" x1="52" y1="76" x2="548" y2="76"/>
<text class="nj-charts-tick nj-charts-tick--r" x="46" y="80">40</text>
<line class="nj-charts-grid" x1="52" y1="16" x2="548" y2="16"/>
<text class="nj-charts-tick nj-charts-tick--r" x="46" y="20">60</text>
<rect class="nj-charts-c2" x="60.0" y="190.0" width="54.9" height="6.0" rx="3"><title>below 1&#215;: 2</title></rect>
<text class="nj-charts-val" x="87.4" y="185.0" text-anchor="middle">2</text>
<text class="nj-charts-tick" x="87.4" y="212.0">below 1&#215;</text>
<rect class="nj-charts-c1" x="130.9" y="133.0" width="54.9" height="63.0" rx="3"><title>1 to 1.5&#215;: 21</title></rect>
<text class="nj-charts-val" x="158.3" y="128.0" text-anchor="middle">21</text>
<text class="nj-charts-tick" x="158.3" y="212.0">1 to 1.5&#215;</text>
<rect class="nj-charts-c1" x="201.7" y="142.0" width="54.9" height="54.0" rx="3"><title>1.5 to 2&#215;: 18</title></rect>
<text class="nj-charts-val" x="229.1" y="137.0" text-anchor="middle">18</text>
<text class="nj-charts-tick" x="229.1" y="212.0">1.5 to 2&#215;</text>
<rect class="nj-charts-c1" x="272.6" y="40.0" width="54.9" height="156.0" rx="3"><title>2 to 3&#215;: 52</title></rect>
<text class="nj-charts-val" x="300.0" y="35.0" text-anchor="middle">52</text>
<text class="nj-charts-tick" x="300.0" y="212.0">2 to 3&#215;</text>
<rect class="nj-charts-c1" x="343.4" y="52.0" width="54.9" height="144.0" rx="3"><title>3 to 5&#215;: 48</title></rect>
<text class="nj-charts-val" x="370.9" y="47.0" text-anchor="middle">48</text>
<text class="nj-charts-tick" x="370.9" y="212.0">3 to 5&#215;</text>
<rect class="nj-charts-c1" x="414.3" y="103.0" width="54.9" height="93.0" rx="3"><title>5 to 10&#215;: 31</title></rect>
<text class="nj-charts-val" x="441.7" y="98.0" text-anchor="middle">31</text>
<text class="nj-charts-tick" x="441.7" y="212.0">5 to 10&#215;</text>
<rect class="nj-charts-c1" x="485.1" y="166.0" width="54.9" height="30.0" rx="3"><title>10&#215; or more: 10</title></rect>
<text class="nj-charts-val" x="512.6" y="161.0" text-anchor="middle">10</text>
<text class="nj-charts-tick" x="512.6" y="212.0">10&#215; or more</text>
<line class="nj-charts-axis" x1="52" y1="196" x2="548" y2="196"/>
<text class="nj-charts-tick" x="300" y="240">speedup over 3.12.0, more is better</text>
<text class="nj-charts-tick" transform="rotate(-90)" x="-106" y="14">number of benchmarks</text>
</svg>

</div>

<p class="nj-caption" markdown>How many of the suite's 182 benchmarks got how much faster. The two below 1× copy
`citm_catalog.json` and `twitter.json` without destroying the copy (0.95× and 0.99×). Every row is in [Appendix
B](#b-3120-against-3130).</p>

The median benchmark got 2.9× as fast. On an Intel MacBook Pro (Skylake), the median is 2.9× as well, but parsing
floating-point numbers gained more (`canada.json` 6.1× instead of 4.1×) and writing integers less (`dump()` 1.4–2.3×
instead of 2.2–3.7×); [Appendix B](#b-3120-against-3130) has both columns. Copying and comparing values gained the
least, and the largest gains come from fixing algorithms rather than tuning them (theme
<a class="nj-theme" href="#theme-7" title="theme 7">7</a>).

Eight themes did most of the work:

<div class="nj-theme-list" markdown>

- <a class="nj-theme" href="#theme-1" title="theme 1">1</a> [Specialize for each input source](#theme-1): a dedicated
  reader for each of strings, streams, and `FILE*`, instead of one character at a time for all of them.
- <a class="nj-theme" href="#theme-2" title="theme 2">2</a> [Work on words, not bytes](#theme-2): 8 bytes per step with
  plain integer arithmetic, 16 with SSE2 and NEON.
- <a class="nj-theme" href="#theme-3" title="theme 3">3</a> [Own the number conversions](#theme-3): no `strtod`, no
  locale.
- <a class="nj-theme" href="#theme-4" title="theme 4">4</a> [Don't do unnecessary work](#theme-4): positions, copies,
  and conversions that only matter on an error or for a rare caller.
- <a class="nj-theme" href="#theme-5" title="theme 5">5</a> [Read the assembly](#theme-5): stack canaries, missed
  inlining, aliasing, and branches the compiler chose.
- <a class="nj-theme" href="#theme-6" title="theme 6">6</a> [Write through a cursor](#theme-6): no virtual call per
  character, no allocation per call, no branch per integer.
- <a class="nj-theme" href="#theme-7" title="theme 7">7</a> [Fix the algorithm first](#theme-7): seven operations were
  quadratic or worse.
- <a class="nj-theme" href="#theme-8" title="theme 8">8</a> [Build a different data structure](#theme-8) when the tree
  is the cost.

</div>

## Where the time went: a timeline

The suite compares two points. To see which change did what, we compiled one small benchmark against the header of each
of the 358 commits on `develop` that changed `json.hpp` or `json_view.hpp` from 3.12.0 to November 7, and of 3.13.0, and
ran all of them interleaved. Four of the eight workloads we followed:

- `parse()` of `citm_catalog.json`: the lexer's structure and whitespace handling, and building many small objects;
- `parse()` of `canada.json`: converting text to floating-point numbers;
- `dump()` of `twitter.json`: writing strings;
- `from_cbor()` of `twitter.json`: reading a binary format.

Each panel shows the speedup over 3.12.0 after each commit, on a logarithmic scale. The badges above the steps name the
theme below that explains them. Moving code around changes a build's speed by a few percent on its own, so only the
larger steps mean something.

<div class="nj-charts-grid-wrap" markdown>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-parse_citm nj-blog-tl-parse_citm-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-parse_citm">parse() citm_catalog.json: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-parse_citm-d">parse() citm_catalog.json: speedup over 3.12.0 at each of 360 commits, ending at 3.8x. Labeled steps, by theme: 4, 1, 4, 4, 2, 4, 1.</desc>
<text class="nj-charts-panel" x="8" y="18">parse() citm_catalog.json</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="160.667" x2="330" y2="160.667"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="164.667">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="113.333" x2="330" y2="113.333"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="117.333">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">8&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.2 45.6,208.2 45.6,207.8 46.4,207.8 46.4,207.5 47.2,207.5 47.2,206.5 48.0,206.5 48.0,208.3 48.8,208.3 48.8,207.3 49.6,207.3 49.6,206.8 50.4,206.8 50.4,207.8 51.2,207.8 51.2,206.8 52.0,206.8 52.0,207.3 52.8,207.3 52.8,207.6 53.6,207.6 53.6,207.8 54.4,207.8 54.4,207.0 55.2,207.0 55.2,207.3 55.9,207.3 55.9,207.2 56.7,207.2 56.7,207.4 57.5,207.4 57.5,207.5 58.3,207.5 58.3,207.4 59.1,207.4 59.1,206.6 59.9,206.6 59.9,207.6 60.7,207.6 60.7,207.6 61.5,207.6 61.5,207.2 62.3,207.2 62.3,207.0 63.1,207.0 63.1,207.6 63.9,207.6 63.9,206.7 64.7,206.7 64.7,207.4 65.5,207.4 65.5,206.8 66.3,206.8 66.3,207.3 67.1,207.3 67.1,207.7 67.9,207.7 67.9,207.9 68.7,207.9 68.7,207.2 69.5,207.2 69.5,206.4 70.3,206.4 70.3,207.6 71.1,207.6 71.1,206.4 71.9,206.4 71.9,208.0 72.7,208.0 72.7,207.4 73.5,207.4 73.5,206.5 74.3,206.5 74.3,207.5 75.1,207.5 75.1,207.2 75.9,207.2 75.9,206.9 76.7,206.9 76.7,207.6 77.5,207.6 77.5,207.6 78.3,207.6 78.3,207.0 79.1,207.0 79.1,206.9 79.8,206.9 79.8,208.0 80.6,208.0 80.6,207.6 81.4,207.6 81.4,206.6 82.2,206.6 82.2,206.8 83.0,206.8 83.0,207.3 83.8,207.3 83.8,206.9 84.6,206.9 84.6,207.6 85.4,207.6 85.4,207.1 86.2,207.1 86.2,207.6 87.0,207.6 87.0,207.9 87.8,207.9 87.8,178.2 88.6,178.2 88.6,177.5 89.4,177.5 89.4,177.7 90.2,177.7 90.2,177.6 91.0,177.6 91.0,177.7 91.8,177.7 91.8,177.1 92.6,177.1 92.6,176.8 93.4,176.8 93.4,177.7 94.2,177.7 94.2,177.6 95.0,177.6 95.0,176.8 95.8,176.8 95.8,177.8 96.6,177.8 96.6,177.0 97.4,177.0 97.4,176.8 98.2,176.8 98.2,178.0 99.0,178.0 99.0,178.1 99.8,178.1 99.8,177.6 100.6,177.6 100.6,177.6 101.4,177.6 101.4,177.4 102.2,177.4 102.2,177.6 103.0,177.6 103.0,177.8 103.7,177.8 103.7,177.5 104.5,177.5 104.5,177.9 105.3,177.9 105.3,177.7 106.1,177.7 106.1,175.9 106.9,175.9 106.9,177.5 107.7,177.5 107.7,177.6 108.5,177.6 108.5,177.6 109.3,177.6 109.3,176.9 110.1,176.9 110.1,177.5 110.9,177.5 110.9,177.4 111.7,177.4 111.7,177.4 112.5,177.4 112.5,176.9 113.3,176.9 113.3,177.9 114.1,177.9 114.1,177.3 114.9,177.3 114.9,176.6 115.7,176.6 115.7,177.4 116.5,177.4 116.5,177.5 117.3,177.5 117.3,177.5 118.1,177.5 118.1,177.4 118.9,177.4 118.9,177.0 119.7,177.0 119.7,177.7 120.5,177.7 120.5,176.2 121.3,176.2 121.3,176.9 122.1,176.9 122.1,177.5 122.9,177.5 122.9,177.8 123.7,177.8 123.7,177.8 124.5,177.8 124.5,177.9 125.3,177.9 125.3,177.3 126.1,177.3 126.1,177.5 126.9,177.5 126.9,177.4 127.6,177.4 127.6,177.1 128.4,177.1 128.4,162.5 129.2,162.5 129.2,162.2 130.0,162.2 130.0,161.8 130.8,161.8 130.8,162.2 131.6,162.2 131.6,161.2 132.4,161.2 132.4,160.7 133.2,160.7 133.2,159.4 134.0,159.4 134.0,160.3 134.8,160.3 134.8,160.4 135.6,160.4 135.6,160.6 136.4,160.6 136.4,159.5 137.2,159.5 137.2,160.4 138.0,160.4 138.0,159.6 138.8,159.6 138.8,160.0 139.6,160.0 139.6,159.9 140.4,159.9 140.4,160.2 141.2,160.2 141.2,159.6 142.0,159.6 142.0,160.8 142.8,160.8 142.8,160.1 143.6,160.1 143.6,159.1 144.4,159.1 144.4,159.7 145.2,159.7 145.2,159.9 146.0,159.9 146.0,160.5 146.8,160.5 146.8,160.2 147.6,160.2 147.6,159.9 148.4,159.9 148.4,160.5 149.2,160.5 149.2,160.5 150.0,160.5 150.0,160.6 150.8,160.6 150.8,159.7 151.5,159.7 151.5,159.5 152.3,159.5 152.3,160.0 153.1,160.0 153.1,160.2 153.9,160.2 153.9,160.0 154.7,160.0 154.7,160.6 155.5,160.6 155.5,159.9 156.3,159.9 156.3,160.2 157.1,160.2 157.1,160.1 157.9,160.1 157.9,160.8 158.7,160.8 158.7,159.2 159.5,159.2 159.5,159.6 160.3,159.6 160.3,159.2 161.1,159.2 161.1,160.0 161.9,160.0 161.9,159.4 162.7,159.4 162.7,159.6 163.5,159.6 163.5,159.5 164.3,159.5 164.3,160.1 165.1,160.1 165.1,159.0 165.9,159.0 165.9,159.4 166.7,159.4 166.7,160.2 167.5,160.2 167.5,161.4 168.3,161.4 168.3,161.7 169.1,161.7 169.1,161.6 169.9,161.6 169.9,160.3 170.7,160.3 170.7,161.1 171.5,161.1 171.5,161.2 172.3,161.2 172.3,161.7 173.1,161.7 173.1,161.2 173.9,161.2 173.9,160.4 174.7,160.4 174.7,161.6 175.4,161.6 175.4,160.6 176.2,160.6 176.2,161.4 177.0,161.4 177.0,161.3 177.8,161.3 177.8,161.3 178.6,161.3 178.6,161.7 179.4,161.7 179.4,161.2 180.2,161.2 180.2,160.1 181.0,160.1 181.0,160.9 181.8,160.9 181.8,161.5 182.6,161.5 182.6,160.6 183.4,160.6 183.4,161.9 184.2,161.9 184.2,161.4 185.0,161.4 185.0,160.1 185.8,160.1 185.8,160.6 186.6,160.6 186.6,162.0 187.4,162.0 187.4,161.5 188.2,161.5 188.2,162.0 189.0,162.0 189.0,161.3 189.8,161.3 189.8,162.3 190.6,162.3 190.6,162.1 191.4,162.1 191.4,160.8 192.2,160.8 192.2,161.5 193.0,161.5 193.0,161.4 193.8,161.4 193.8,162.2 194.6,162.2 194.6,161.4 195.4,161.4 195.4,161.4 196.2,161.4 196.2,161.8 197.0,161.8 197.0,160.7 197.8,160.7 197.8,160.5 198.6,160.5 198.6,160.5 199.3,160.5 199.3,159.3 200.1,159.3 200.1,159.4 200.9,159.4 200.9,160.4 201.7,160.4 201.7,160.1 202.5,160.1 202.5,160.4 203.3,160.4 203.3,160.4 204.1,160.4 204.1,160.8 204.9,160.8 204.9,159.8 205.7,159.8 205.7,159.4 206.5,159.4 206.5,160.5 207.3,160.5 207.3,160.1 208.1,160.1 208.1,160.7 208.9,160.7 208.9,160.6 209.7,160.6 209.7,159.5 210.5,159.5 210.5,161.1 211.3,161.1 211.3,161.3 212.1,161.3 212.1,161.0 212.9,161.0 212.9,160.8 213.7,160.8 213.7,159.6 214.5,159.6 214.5,161.0 215.3,161.0 215.3,160.6 216.1,160.6 216.1,160.6 216.9,160.6 216.9,161.4 217.7,161.4 217.7,159.8 218.5,159.8 218.5,160.2 219.3,160.2 219.3,155.4 220.1,155.4 220.1,156.1 220.9,156.1 220.9,155.2 221.7,155.2 221.7,156.3 222.5,156.3 222.5,156.1 223.2,156.1 223.2,155.8 224.0,155.8 224.0,156.5 224.8,156.5 224.8,155.8 225.6,155.8 225.6,155.9 226.4,155.9 226.4,155.7 227.2,155.7 227.2,155.0 228.0,155.0 228.0,156.1 228.8,156.1 228.8,156.5 229.6,156.5 229.6,156.3 230.4,156.3 230.4,155.6 231.2,155.6 231.2,154.9 232.0,154.9 232.0,155.8 232.8,155.8 232.8,155.5 233.6,155.5 233.6,155.0 234.4,155.0 234.4,155.2 235.2,155.2 235.2,155.4 236.0,155.4 236.0,155.4 236.8,155.4 236.8,155.6 237.6,155.6 237.6,156.0 238.4,156.0 238.4,155.7 239.2,155.7 239.2,147.1 240.0,147.1 240.0,138.2 240.8,138.2 240.8,138.0 241.6,138.0 241.6,137.7 242.4,137.7 242.4,137.6 243.2,137.6 243.2,137.8 244.0,137.8 244.0,137.7 244.8,137.7 244.8,137.2 245.6,137.2 245.6,137.3 246.4,137.3 246.4,137.5 247.1,137.5 247.1,137.1 247.9,137.1 247.9,135.2 248.7,135.2 248.7,135.1 249.5,135.1 249.5,132.3 250.3,132.3 250.3,133.6 251.1,133.6 251.1,133.4 251.9,133.4 251.9,133.9 252.7,133.9 252.7,133.2 253.5,133.2 253.5,132.9 254.3,132.9 254.3,131.7 255.1,131.7 255.1,132.8 255.9,132.8 255.9,133.0 256.7,133.0 256.7,132.8 257.5,132.8 257.5,132.8 258.3,132.8 258.3,132.6 259.1,132.6 259.1,133.3 259.9,133.3 259.9,131.7 260.7,131.7 260.7,132.3 261.5,132.3 261.5,132.7 262.3,132.7 262.3,133.3 263.1,133.3 263.1,131.5 263.9,131.5 263.9,132.3 264.7,132.3 264.7,133.4 265.5,133.4 265.5,132.1 266.3,132.1 266.3,132.8 267.1,132.8 267.1,131.2 267.9,131.2 267.9,130.8 268.7,130.8 268.7,130.8 269.5,130.8 269.5,129.9 270.3,129.9 270.3,130.1 271.0,130.1 271.0,131.1 271.8,131.1 271.8,129.7 272.6,129.7 272.6,129.2 273.4,129.2 273.4,129.7 274.2,129.7 274.2,129.8 275.0,129.8 275.0,128.6 275.8,128.6 275.8,130.0 276.6,130.0 276.6,130.0 277.4,130.0 277.4,129.4 278.2,129.4 278.2,129.3 279.0,129.3 279.0,130.1 279.8,130.1 279.8,129.6 280.6,129.6 280.6,125.7 281.4,125.7 281.4,125.7 282.2,125.7 282.2,125.7 283.0,125.7 283.0,126.1 283.8,126.1 283.8,126.1 284.6,126.1 284.6,125.2 285.4,125.2 285.4,125.8 286.2,125.8 286.2,126.1 287.0,126.1 287.0,125.7 287.8,125.7 287.8,125.7 288.6,125.7 288.6,125.7 289.4,125.7 289.4,124.7 290.2,124.7 290.2,126.1 291.0,126.1 291.0,126.2 291.8,126.2 291.8,125.8 292.6,125.8 292.6,126.2 293.4,126.2 293.4,125.9 294.2,125.9 294.2,125.8 294.9,125.8 294.9,125.8 295.7,125.8 295.7,125.7 296.5,125.7 296.5,126.6 297.3,126.6 297.3,125.5 298.1,125.5 298.1,126.4 298.9,126.4 298.9,126.1 299.7,126.1 299.7,126.7 300.5,126.7 300.5,125.8 301.3,125.8 301.3,125.9 302.1,125.9 302.1,125.5 302.9,125.5 302.9,126.4 303.7,126.4 303.7,126.9 304.5,126.9 304.5,126.0 305.3,126.0 305.3,125.8 306.1,125.8 306.1,126.2 306.9,126.2 306.9,126.3 307.7,126.3 307.7,125.9 308.5,125.9 308.5,125.4 309.3,125.4 309.3,127.1 310.1,127.1 310.1,126.0 310.9,126.0 310.9,126.4 311.7,126.4 311.7,125.6 312.5,125.6 312.5,125.7 313.3,125.7 313.3,125.5 314.1,125.5 314.1,125.5 314.9,125.5 314.9,125.4 315.7,125.4 315.7,126.1 316.5,126.1 316.5,125.4 317.3,125.4 317.3,125.9 318.1,125.9 318.1,125.5 318.8,125.5 318.8,125.9 319.6,125.9 319.6,125.0 320.4,125.0 320.4,124.6 321.2,124.6 321.2,125.0 322.0,125.0 322.0,124.9 322.8,124.9 322.8,125.0 323.6,125.0 323.6,125.1 324.4,125.1 324.4,125.5 325.2,125.5 325.2,125.1 326.0,125.1 326.0,125.6 326.8,125.6 326.8,125.5 327.6,125.5 327.6,124.9 328.4,124.9 328.4,124.8 329.2,124.8 329.2,125.0 330.0,125.0 330.0,116.6"/>
<circle class="nj-charts-json-dot" cx="87.8" cy="178.2" r="3.5"><title>#5234: 1.55&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="87.8" y1="54.0" x2="87.8" y2="173.2"/>
<circle class="nj-theme-dot" cx="87.8" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="87.8" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="128.4" cy="162.5" r="3.5"><title>#5283: 1.95&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="128.4" y1="54.0" x2="128.4" y2="157.5"/>
<circle class="nj-theme-dot" cx="128.4" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="128.4" y="50.0" text-anchor="middle">1</text>
<circle class="nj-charts-json-dot" cx="219.3" cy="155.4" r="3.5"><title>#5592: 2.2&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="219.3" y1="54.0" x2="219.3" y2="150.4"/>
<circle class="nj-theme-dot" cx="219.3" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="219.3" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="239.2" cy="147.1" r="3.5"><title>#5809: 2.4&#215;</title></circle>
<circle class="nj-charts-json-dot" cx="240.0" cy="138.2" r="3.5"><title>#5810: 2.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="240.0" y1="36.0" x2="240.0" y2="133.2"/>
<circle class="nj-theme-dot" cx="231.0" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="231.0" y="32.0" text-anchor="middle">4</text>
<circle class="nj-theme-dot" cx="249.0" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="249.0" y="32.0" text-anchor="middle">2</text>
<circle class="nj-charts-json-dot" cx="280.6" cy="125.7" r="3.5"><title>#5882: 3.3&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="280.6" y1="54.0" x2="280.6" y2="120.7"/>
<circle class="nj-theme-dot" cx="280.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="280.6" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="330.0" cy="116.6" r="3.5"><title>#6031: 3.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="330.0" y1="54.0" x2="330.0" y2="111.6"/>
<circle class="nj-theme-dot" cx="322.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="322.5" y="50.0" text-anchor="middle">1</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-parse_canada nj-blog-tl-parse_canada-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-parse_canada">parse() canada.json: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-parse_canada-d">parse() canada.json: speedup over 3.12.0 at each of 360 commits, ending at 3.3x. Labeled steps, by theme: 4, 1, 3, 3, 3, 4, 1.</desc>
<text class="nj-charts-panel" x="8" y="18">parse() canada.json</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="160.667" x2="330" y2="160.667"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="164.667">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="113.333" x2="330" y2="113.333"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="117.333">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">8&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.1 45.6,208.1 45.6,208.1 46.4,208.1 46.4,207.8 47.2,207.8 47.2,207.5 48.0,207.5 48.0,208.0 48.8,208.0 48.8,208.1 49.6,208.1 49.6,207.8 50.4,207.8 50.4,208.3 51.2,208.3 51.2,207.5 52.0,207.5 52.0,208.0 52.8,208.0 52.8,208.8 53.6,208.8 53.6,208.3 54.4,208.3 54.4,208.1 55.2,208.1 55.2,207.8 55.9,207.8 55.9,209.2 56.7,209.2 56.7,208.4 57.5,208.4 57.5,208.1 58.3,208.1 58.3,208.1 59.1,208.1 59.1,207.3 59.9,207.3 59.9,207.8 60.7,207.8 60.7,207.7 61.5,207.7 61.5,208.1 62.3,208.1 62.3,208.3 63.1,208.3 63.1,207.8 63.9,207.8 63.9,207.6 64.7,207.6 64.7,208.2 65.5,208.2 65.5,207.5 66.3,207.5 66.3,207.8 67.1,207.8 67.1,207.9 67.9,207.9 67.9,207.9 68.7,207.9 68.7,207.6 69.5,207.6 69.5,207.7 70.3,207.7 70.3,208.0 71.1,208.0 71.1,208.1 71.9,208.1 71.9,207.9 72.7,207.9 72.7,207.9 73.5,207.9 73.5,207.4 74.3,207.4 74.3,207.7 75.1,207.7 75.1,207.9 75.9,207.9 75.9,207.5 76.7,207.5 76.7,207.8 77.5,207.8 77.5,208.4 78.3,208.4 78.3,207.0 79.1,207.0 79.1,208.0 79.8,208.0 79.8,208.5 80.6,208.5 80.6,208.0 81.4,208.0 81.4,207.8 82.2,207.8 82.2,208.3 83.0,208.3 83.0,208.0 83.8,208.0 83.8,207.7 84.6,207.7 84.6,207.9 85.4,207.9 85.4,207.6 86.2,207.6 86.2,207.7 87.0,207.7 87.0,208.3 87.8,208.3 87.8,201.0 88.6,201.0 88.6,201.3 89.4,201.3 89.4,200.6 90.2,200.6 90.2,200.7 91.0,200.7 91.0,201.2 91.8,201.2 91.8,200.0 92.6,200.0 92.6,200.8 93.4,200.8 93.4,201.4 94.2,201.4 94.2,200.9 95.0,200.9 95.0,200.6 95.8,200.6 95.8,201.0 96.6,201.0 96.6,200.8 97.4,200.8 97.4,201.1 98.2,201.1 98.2,201.1 99.0,201.1 99.0,201.1 99.8,201.1 99.8,200.6 100.6,200.6 100.6,201.3 101.4,201.3 101.4,201.3 102.2,201.3 102.2,201.0 103.0,201.0 103.0,201.0 103.7,201.0 103.7,201.0 104.5,201.0 104.5,201.4 105.3,201.4 105.3,201.3 106.1,201.3 106.1,199.5 106.9,199.5 106.9,200.4 107.7,200.4 107.7,201.2 108.5,201.2 108.5,200.7 109.3,200.7 109.3,200.2 110.1,200.2 110.1,200.5 110.9,200.5 110.9,200.4 111.7,200.4 111.7,200.4 112.5,200.4 112.5,201.1 113.3,201.1 113.3,201.0 114.1,201.0 114.1,201.4 114.9,201.4 114.9,199.9 115.7,199.9 115.7,201.0 116.5,201.0 116.5,201.1 117.3,201.1 117.3,200.5 118.1,200.5 118.1,200.7 118.9,200.7 118.9,201.3 119.7,201.3 119.7,200.6 120.5,200.6 120.5,200.8 121.3,200.8 121.3,200.4 122.1,200.4 122.1,200.7 122.9,200.7 122.9,200.8 123.7,200.8 123.7,201.0 124.5,201.0 124.5,201.2 125.3,201.2 125.3,200.8 126.1,200.8 126.1,201.1 126.9,201.1 126.9,200.9 127.6,200.9 127.6,200.7 128.4,200.7 128.4,181.8 129.2,181.8 129.2,182.4 130.0,182.4 130.0,182.8 130.8,182.8 130.8,181.9 131.6,181.9 131.6,181.6 132.4,181.6 132.4,182.6 133.2,182.6 133.2,181.8 134.0,181.8 134.0,181.5 134.8,181.5 134.8,182.5 135.6,182.5 135.6,183.2 136.4,183.2 136.4,181.4 137.2,181.4 137.2,182.8 138.0,182.8 138.0,182.1 138.8,182.1 138.8,182.7 139.6,182.7 139.6,181.6 140.4,181.6 140.4,182.5 141.2,182.5 141.2,182.7 142.0,182.7 142.0,182.5 142.8,182.5 142.8,182.1 143.6,182.1 143.6,180.8 144.4,180.8 144.4,182.5 145.2,182.5 145.2,181.7 146.0,181.7 146.0,182.9 146.8,182.9 146.8,182.5 147.6,182.5 147.6,181.8 148.4,181.8 148.4,182.2 149.2,182.2 149.2,184.2 150.0,184.2 150.0,183.5 150.8,183.5 150.8,182.1 151.5,182.1 151.5,181.2 152.3,181.2 152.3,182.2 153.1,182.2 153.1,182.1 153.9,182.1 153.9,181.7 154.7,181.7 154.7,181.8 155.5,181.8 155.5,181.7 156.3,181.7 156.3,182.0 157.1,182.0 157.1,181.7 157.9,181.7 157.9,183.2 158.7,183.2 158.7,182.6 159.5,182.6 159.5,181.4 160.3,181.4 160.3,181.9 161.1,181.9 161.1,181.7 161.9,181.7 161.9,181.6 162.7,181.6 162.7,182.6 163.5,182.6 163.5,182.1 164.3,182.1 164.3,181.7 165.1,181.7 165.1,181.7 165.9,181.7 165.9,182.2 166.7,182.2 166.7,182.0 167.5,182.0 167.5,182.8 168.3,182.8 168.3,188.0 169.1,188.0 169.1,187.6 169.9,187.6 169.9,181.2 170.7,181.2 170.7,181.7 171.5,181.7 171.5,181.8 172.3,181.8 172.3,181.6 173.1,181.6 173.1,181.9 173.9,181.9 173.9,181.3 174.7,181.3 174.7,181.5 175.4,181.5 175.4,181.1 176.2,181.1 176.2,181.0 177.0,181.0 177.0,181.4 177.8,181.4 177.8,181.5 178.6,181.5 178.6,181.4 179.4,181.4 179.4,181.4 180.2,181.4 180.2,181.0 181.0,181.0 181.0,180.4 181.8,180.4 181.8,182.1 182.6,182.1 182.6,181.7 183.4,181.7 183.4,181.6 184.2,181.6 184.2,181.4 185.0,181.4 185.0,180.9 185.8,180.9 185.8,181.3 186.6,181.3 186.6,181.5 187.4,181.5 187.4,181.7 188.2,181.7 188.2,182.0 189.0,182.0 189.0,180.4 189.8,180.4 189.8,182.3 190.6,182.3 190.6,182.2 191.4,182.2 191.4,180.9 192.2,180.9 192.2,181.6 193.0,181.6 193.0,180.8 193.8,180.8 193.8,182.2 194.6,182.2 194.6,181.9 195.4,181.9 195.4,180.9 196.2,180.9 196.2,181.6 197.0,181.6 197.0,181.6 197.8,181.6 197.8,180.6 198.6,180.6 198.6,181.8 199.3,181.8 199.3,179.8 200.1,179.8 200.1,180.7 200.9,180.7 200.9,180.4 201.7,180.4 201.7,181.0 202.5,181.0 202.5,181.1 203.3,181.1 203.3,180.8 204.1,180.8 204.1,180.9 204.9,180.9 204.9,180.4 205.7,180.4 205.7,180.1 206.5,180.1 206.5,181.6 207.3,181.6 207.3,180.8 208.1,180.8 208.1,180.5 208.9,180.5 208.9,180.3 209.7,180.3 209.7,180.0 210.5,180.0 210.5,180.9 211.3,180.9 211.3,180.8 212.1,180.8 212.1,180.9 212.9,180.9 212.9,181.5 213.7,181.5 213.7,180.3 214.5,180.3 214.5,181.2 215.3,181.2 215.3,180.6 216.1,180.6 216.1,181.3 216.9,181.3 216.9,181.3 217.7,181.3 217.7,180.7 218.5,180.7 218.5,176.3 219.3,176.3 219.3,172.5 220.1,172.5 220.1,173.1 220.9,173.1 220.9,172.6 221.7,172.6 221.7,173.2 222.5,173.2 222.5,173.5 223.2,173.5 223.2,173.2 224.0,173.2 224.0,173.3 224.8,173.3 224.8,173.3 225.6,173.3 225.6,173.4 226.4,173.4 226.4,173.1 227.2,173.1 227.2,172.6 228.0,172.6 228.0,172.8 228.8,172.8 228.8,173.6 229.6,173.6 229.6,172.7 230.4,172.7 230.4,172.6 231.2,172.6 231.2,172.0 232.0,172.0 232.0,172.6 232.8,172.6 232.8,172.5 233.6,172.5 233.6,173.3 234.4,173.3 234.4,172.7 235.2,172.7 235.2,173.6 236.0,173.6 236.0,172.5 236.8,172.5 236.8,172.1 237.6,172.1 237.6,173.1 238.4,173.1 238.4,173.2 239.2,173.2 239.2,171.4 240.0,171.4 240.0,172.5 240.8,172.5 240.8,172.5 241.6,172.5 241.6,162.6 242.4,162.6 242.4,162.1 243.2,162.1 243.2,162.8 244.0,162.8 244.0,162.5 244.8,162.5 244.8,163.0 245.6,163.0 245.6,162.7 246.4,162.7 246.4,162.6 247.1,162.6 247.1,162.8 247.9,162.8 247.9,159.8 248.7,159.8 248.7,160.2 249.5,160.2 249.5,161.6 250.3,161.6 250.3,161.3 251.1,161.3 251.1,161.8 251.9,161.8 251.9,160.8 252.7,160.8 252.7,161.0 253.5,161.0 253.5,160.7 254.3,160.7 254.3,159.7 255.1,159.7 255.1,160.3 255.9,160.3 255.9,161.3 256.7,161.3 256.7,161.0 257.5,161.0 257.5,160.8 258.3,160.8 258.3,159.6 259.1,159.6 259.1,160.7 259.9,160.7 259.9,159.5 260.7,159.5 260.7,160.6 261.5,160.6 261.5,159.7 262.3,159.7 262.3,160.8 263.1,160.8 263.1,159.9 263.9,159.9 263.9,161.4 264.7,161.4 264.7,161.0 265.5,161.0 265.5,162.1 266.3,162.1 266.3,162.7 267.1,162.7 267.1,154.3 267.9,154.3 267.9,150.2 268.7,150.2 268.7,150.4 269.5,150.4 269.5,149.9 270.3,149.9 270.3,150.7 271.0,150.7 271.0,149.4 271.8,149.4 271.8,149.0 272.6,149.0 272.6,150.4 273.4,150.4 273.4,148.9 274.2,148.9 274.2,149.2 275.0,149.2 275.0,149.3 275.8,149.3 275.8,149.9 276.6,149.9 276.6,148.7 277.4,148.7 277.4,148.9 278.2,148.9 278.2,149.5 279.0,149.5 279.0,149.6 279.8,149.6 279.8,148.8 280.6,148.8 280.6,137.5 281.4,137.5 281.4,137.6 282.2,137.6 282.2,137.4 283.0,137.4 283.0,137.6 283.8,137.6 283.8,137.3 284.6,137.3 284.6,136.9 285.4,136.9 285.4,137.3 286.2,137.3 286.2,137.6 287.0,137.6 287.0,137.3 287.8,137.3 287.8,137.3 288.6,137.3 288.6,137.2 289.4,137.2 289.4,136.4 290.2,136.4 290.2,137.8 291.0,137.8 291.0,137.5 291.8,137.5 291.8,137.3 292.6,137.3 292.6,137.4 293.4,137.4 293.4,137.4 294.2,137.4 294.2,137.5 294.9,137.5 294.9,137.9 295.7,137.9 295.7,137.3 296.5,137.3 296.5,140.3 297.3,140.3 297.3,137.2 298.1,137.2 298.1,138.2 298.9,138.2 298.9,138.1 299.7,138.1 299.7,137.7 300.5,137.7 300.5,137.0 301.3,137.0 301.3,137.6 302.1,137.6 302.1,137.3 302.9,137.3 302.9,138.1 303.7,138.1 303.7,138.5 304.5,138.5 304.5,137.2 305.3,137.2 305.3,137.3 306.1,137.3 306.1,137.7 306.9,137.7 306.9,138.5 307.7,138.5 307.7,137.5 308.5,137.5 308.5,136.4 309.3,136.4 309.3,137.7 310.1,137.7 310.1,137.4 310.9,137.4 310.9,136.9 311.7,136.9 311.7,136.4 312.5,136.4 312.5,136.4 313.3,136.4 313.3,136.5 314.1,136.5 314.1,136.7 314.9,136.7 314.9,136.9 315.7,136.9 315.7,137.0 316.5,137.0 316.5,136.9 317.3,136.9 317.3,137.1 318.1,137.1 318.1,138.6 318.8,138.6 318.8,138.8 319.6,138.8 319.6,138.1 320.4,138.1 320.4,138.0 321.2,138.0 321.2,138.3 322.0,138.3 322.0,137.8 322.8,137.8 322.8,137.6 323.6,137.6 323.6,138.0 324.4,138.0 324.4,137.9 325.2,137.9 325.2,138.2 326.0,138.2 326.0,137.8 326.8,137.8 326.8,138.4 327.6,138.4 327.6,137.9 328.4,137.9 328.4,137.8 329.2,137.8 329.2,138.3 330.0,138.3 330.0,126.8"/>
<circle class="nj-charts-json-dot" cx="87.8" cy="201.0" r="3.5"><title>#5234: 1.11&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="87.8" y1="54.0" x2="87.8" y2="196.0"/>
<circle class="nj-theme-dot" cx="87.8" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="87.8" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="128.4" cy="181.8" r="3.5"><title>#5283: 1.47&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="128.4" y1="54.0" x2="128.4" y2="176.8"/>
<circle class="nj-theme-dot" cx="128.4" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="128.4" y="50.0" text-anchor="middle">1</text>
<circle class="nj-charts-json-dot" cx="169.9" cy="181.2" r="3.5"><title>#5617: 1.48&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="169.9" y1="54.0" x2="169.9" y2="176.2"/>
<circle class="nj-theme-dot" cx="169.9" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="169.9" y="50.0" text-anchor="middle">3</text>
<circle class="nj-charts-json-dot" cx="241.6" cy="162.6" r="3.5"><title>#5738: 1.95&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="241.6" y1="54.0" x2="241.6" y2="157.6"/>
<circle class="nj-theme-dot" cx="241.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="241.6" y="50.0" text-anchor="middle">3</text>
<circle class="nj-charts-json-dot" cx="267.1" cy="154.3" r="3.5"><title>#5851: 2.2&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="267.1" y1="54.0" x2="267.1" y2="149.3"/>
<circle class="nj-theme-dot" cx="267.1" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="267.1" y="50.0" text-anchor="middle">3</text>
<circle class="nj-charts-json-dot" cx="280.6" cy="137.5" r="3.5"><title>#5882: 2.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="280.6" y1="36.0" x2="280.6" y2="132.5"/>
<circle class="nj-theme-dot" cx="280.6" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="280.6" y="32.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="330.0" cy="126.8" r="3.5"><title>#6031: 3.3&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="330.0" y1="54.0" x2="330.0" y2="121.8"/>
<circle class="nj-theme-dot" cx="322.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="322.5" y="50.0" text-anchor="middle">1</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-dump_twitter nj-blog-tl-dump_twitter-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-dump_twitter">dump() twitter.json: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-dump_twitter-d">dump() twitter.json: speedup over 3.12.0 at each of 360 commits, ending at 6.8x. Labeled steps, by theme: 6, 2, 2, 2.</desc>
<text class="nj-charts-panel" x="8" y="18">dump() twitter.json</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="172.5" x2="330" y2="172.5"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="176.5">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="137" x2="330" y2="137"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="141">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="101.5" x2="330" y2="101.5"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="105.5">8&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">16&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.0 45.6,208.0 45.6,207.2 46.4,207.2 46.4,207.9 47.2,207.9 47.2,206.8 48.0,206.8 48.0,208.0 48.8,208.0 48.8,207.4 49.6,207.4 49.6,207.3 50.4,207.3 50.4,208.0 51.2,208.0 51.2,206.8 52.0,206.8 52.0,207.2 52.8,207.2 52.8,208.0 53.6,208.0 53.6,207.2 54.4,207.2 54.4,207.5 55.2,207.5 55.2,206.8 55.9,206.8 55.9,206.9 56.7,206.9 56.7,207.5 57.5,207.5 57.5,207.3 58.3,207.3 58.3,207.8 59.1,207.8 59.1,206.8 59.9,206.8 59.9,207.8 60.7,207.8 60.7,207.4 61.5,207.4 61.5,208.0 62.3,208.0 62.3,207.4 63.1,207.4 63.1,207.3 63.9,207.3 63.9,206.9 64.7,206.9 64.7,207.3 65.5,207.3 65.5,207.4 66.3,207.4 66.3,207.6 67.1,207.6 67.1,207.5 67.9,207.5 67.9,207.6 68.7,207.6 68.7,207.4 69.5,207.4 69.5,207.2 70.3,207.2 70.3,207.1 71.1,207.1 71.1,207.3 71.9,207.3 71.9,207.7 72.7,207.7 72.7,207.8 73.5,207.8 73.5,206.9 74.3,206.9 74.3,207.6 75.1,207.6 75.1,207.0 75.9,207.0 75.9,207.0 76.7,207.0 76.7,207.3 77.5,207.3 77.5,207.6 78.3,207.6 78.3,206.8 79.1,206.8 79.1,207.7 79.8,207.7 79.8,207.4 80.6,207.4 80.6,207.5 81.4,207.5 81.4,207.1 82.2,207.1 82.2,207.3 83.0,207.3 83.0,207.5 83.8,207.5 83.8,207.3 84.6,207.3 84.6,207.3 85.4,207.3 85.4,206.9 86.2,206.9 86.2,207.4 87.0,207.4 87.0,207.9 87.8,207.9 87.8,207.3 88.6,207.3 88.6,206.8 89.4,206.8 89.4,207.6 90.2,207.6 90.2,207.7 91.0,207.7 91.0,208.6 91.8,208.6 91.8,208.5 92.6,208.5 92.6,208.6 93.4,208.6 93.4,209.2 94.2,209.2 94.2,208.5 95.0,208.5 95.0,208.2 95.8,208.2 95.8,209.3 96.6,209.3 96.6,208.4 97.4,208.4 97.4,208.4 98.2,208.4 98.2,209.0 99.0,209.0 99.0,209.0 99.8,209.0 99.8,208.7 100.6,208.7 100.6,208.9 101.4,208.9 101.4,208.7 102.2,208.7 102.2,209.0 103.0,209.0 103.0,208.8 103.7,208.8 103.7,208.7 104.5,208.7 104.5,209.3 105.3,209.3 105.3,208.6 106.1,208.6 106.1,208.5 106.9,208.5 106.9,208.4 107.7,208.4 107.7,208.0 108.5,208.0 108.5,208.9 109.3,208.9 109.3,208.6 110.1,208.6 110.1,208.9 110.9,208.9 110.9,208.1 111.7,208.1 111.7,208.0 112.5,208.0 112.5,208.6 113.3,208.6 113.3,208.5 114.1,208.5 114.1,209.1 114.9,209.1 114.9,208.0 115.7,208.0 115.7,209.1 116.5,209.1 116.5,208.9 117.3,208.9 117.3,208.5 118.1,208.5 118.1,209.1 118.9,209.1 118.9,209.0 119.7,209.0 119.7,208.8 120.5,208.8 120.5,208.6 121.3,208.6 121.3,208.6 122.1,208.6 122.1,208.2 122.9,208.2 122.9,209.0 123.7,209.0 123.7,209.2 124.5,209.2 124.5,209.1 125.3,209.1 125.3,209.2 126.1,209.2 126.1,209.2 126.9,209.2 126.9,208.5 127.6,208.5 127.6,208.7 128.4,208.7 128.4,209.5 129.2,209.5 129.2,208.4 130.0,208.4 130.0,147.4 130.8,147.4 130.8,148.3 131.6,148.3 131.6,148.4 132.4,148.4 132.4,147.5 133.2,147.5 133.2,147.5 134.0,147.5 134.0,147.7 134.8,147.7 134.8,148.2 135.6,148.2 135.6,148.2 136.4,148.2 136.4,147.3 137.2,147.3 137.2,148.1 138.0,148.1 138.0,147.2 138.8,147.2 138.8,147.5 139.6,147.5 139.6,147.3 140.4,147.3 140.4,148.4 141.2,148.4 141.2,147.4 142.0,147.4 142.0,148.3 142.8,148.3 142.8,148.5 143.6,148.5 143.6,147.7 144.4,147.7 144.4,147.8 145.2,147.8 145.2,148.0 146.0,148.0 146.0,148.5 146.8,148.5 146.8,148.0 147.6,148.0 147.6,148.1 148.4,148.1 148.4,148.2 149.2,148.2 149.2,148.3 150.0,148.3 150.0,149.0 150.8,149.0 150.8,148.7 151.5,148.7 151.5,148.2 152.3,148.2 152.3,148.1 153.1,148.1 153.1,148.9 153.9,148.9 153.9,147.7 154.7,147.7 154.7,149.2 155.5,149.2 155.5,149.1 156.3,149.1 156.3,148.8 157.1,148.8 157.1,148.1 157.9,148.1 157.9,148.7 158.7,148.7 158.7,147.7 159.5,147.7 159.5,147.9 160.3,147.9 160.3,147.7 161.1,147.7 161.1,148.3 161.9,148.3 161.9,148.0 162.7,148.0 162.7,148.2 163.5,148.2 163.5,148.4 164.3,148.4 164.3,148.3 165.1,148.3 165.1,148.1 165.9,148.1 165.9,149.0 166.7,149.0 166.7,147.8 167.5,147.8 167.5,148.8 168.3,148.8 168.3,148.3 169.1,148.3 169.1,148.0 169.9,148.0 169.9,147.8 170.7,147.8 170.7,148.0 171.5,148.0 171.5,147.7 172.3,147.7 172.3,148.2 173.1,148.2 173.1,147.1 173.9,147.1 173.9,147.9 174.7,147.9 174.7,147.9 175.4,147.9 175.4,147.9 176.2,147.9 176.2,147.7 177.0,147.7 177.0,148.0 177.8,148.0 177.8,147.4 178.6,147.4 178.6,147.5 179.4,147.5 179.4,147.5 180.2,147.5 180.2,147.0 181.0,147.0 181.0,147.0 181.8,147.0 181.8,148.2 182.6,148.2 182.6,147.7 183.4,147.7 183.4,148.0 184.2,148.0 184.2,148.2 185.0,148.2 185.0,147.7 185.8,147.7 185.8,147.8 186.6,147.8 186.6,148.2 187.4,148.2 187.4,148.3 188.2,148.3 188.2,148.5 189.0,148.5 189.0,148.1 189.8,148.1 189.8,147.9 190.6,147.9 190.6,148.2 191.4,148.2 191.4,147.5 192.2,147.5 192.2,148.1 193.0,148.1 193.0,147.6 193.8,147.6 193.8,148.4 194.6,148.4 194.6,148.2 195.4,148.2 195.4,148.3 196.2,148.3 196.2,148.7 197.0,148.7 197.0,149.4 197.8,149.4 197.8,148.7 198.6,148.7 198.6,149.5 199.3,149.5 199.3,148.2 200.1,148.2 200.1,148.5 200.9,148.5 200.9,149.1 201.7,149.1 201.7,148.8 202.5,148.8 202.5,149.2 203.3,149.2 203.3,149.3 204.1,149.3 204.1,149.1 204.9,149.1 204.9,148.6 205.7,148.6 205.7,148.9 206.5,148.9 206.5,148.5 207.3,148.5 207.3,148.9 208.1,148.9 208.1,149.0 208.9,149.0 208.9,149.0 209.7,149.0 209.7,148.5 210.5,148.5 210.5,149.1 211.3,149.1 211.3,149.2 212.1,149.2 212.1,148.3 212.9,148.3 212.9,149.4 213.7,149.4 213.7,148.3 214.5,148.3 214.5,149.1 215.3,149.1 215.3,149.0 216.1,149.0 216.1,148.7 216.9,148.7 216.9,149.1 217.7,149.1 217.7,149.0 218.5,149.0 218.5,149.7 219.3,149.7 219.3,148.6 220.1,148.6 220.1,148.4 220.9,148.4 220.9,147.9 221.7,147.9 221.7,148.7 222.5,148.7 222.5,149.0 223.2,149.0 223.2,148.5 224.0,148.5 224.0,149.2 224.8,149.2 224.8,149.0 225.6,149.0 225.6,148.9 226.4,148.9 226.4,148.6 227.2,148.6 227.2,148.6 228.0,148.6 228.0,149.1 228.8,149.1 228.8,149.7 229.6,149.7 229.6,149.4 230.4,149.4 230.4,149.0 231.2,149.0 231.2,149.5 232.0,149.5 232.0,149.5 232.8,149.5 232.8,149.5 233.6,149.5 233.6,149.5 234.4,149.5 234.4,149.1 235.2,149.1 235.2,148.8 236.0,148.8 236.0,149.4 236.8,149.4 236.8,148.5 237.6,148.5 237.6,149.4 238.4,149.4 238.4,149.4 239.2,149.4 239.2,149.2 240.0,149.2 240.0,150.2 240.8,150.2 240.8,149.9 241.6,149.9 241.6,139.0 242.4,139.0 242.4,137.5 243.2,137.5 243.2,137.6 244.0,137.6 244.0,137.9 244.8,137.9 244.8,137.8 245.6,137.8 245.6,138.0 246.4,138.0 246.4,138.0 247.1,138.0 247.1,137.9 247.9,137.9 247.9,137.8 248.7,137.8 248.7,137.6 249.5,137.6 249.5,137.9 250.3,137.9 250.3,137.3 251.1,137.3 251.1,137.8 251.9,137.8 251.9,137.8 252.7,137.8 252.7,138.0 253.5,138.0 253.5,137.0 254.3,137.0 254.3,135.9 255.1,135.9 255.1,136.8 255.9,136.8 255.9,136.8 256.7,136.8 256.7,137.3 257.5,137.3 257.5,137.3 258.3,137.3 258.3,137.5 259.1,137.5 259.1,137.3 259.9,137.3 259.9,136.1 260.7,136.1 260.7,136.9 261.5,136.9 261.5,136.6 262.3,136.6 262.3,136.1 263.1,136.1 263.1,136.2 263.9,136.2 263.9,136.9 264.7,136.9 264.7,136.8 265.5,136.8 265.5,137.1 266.3,137.1 266.3,137.0 267.1,137.0 267.1,136.9 267.9,136.9 267.9,137.2 268.7,137.2 268.7,134.2 269.5,134.2 269.5,135.2 270.3,135.2 270.3,134.0 271.0,134.0 271.0,131.0 271.8,131.0 271.8,129.9 272.6,129.9 272.6,130.2 273.4,130.2 273.4,130.2 274.2,130.2 274.2,130.3 275.0,130.3 275.0,130.8 275.8,130.8 275.8,130.5 276.6,130.5 276.6,109.6 277.4,109.6 277.4,109.5 278.2,109.5 278.2,109.8 279.0,109.8 279.0,109.8 279.8,109.8 279.8,109.3 280.6,109.3 280.6,109.2 281.4,109.2 281.4,109.6 282.2,109.6 282.2,110.0 283.0,110.0 283.0,110.2 283.8,110.2 283.8,110.6 284.6,110.6 284.6,109.6 285.4,109.6 285.4,110.2 286.2,110.2 286.2,109.7 287.0,109.7 287.0,109.5 287.8,109.5 287.8,110.4 288.6,110.4 288.6,110.1 289.4,110.1 289.4,109.6 290.2,109.6 290.2,110.4 291.0,110.4 291.0,110.5 291.8,110.5 291.8,110.2 292.6,110.2 292.6,110.2 293.4,110.2 293.4,110.5 294.2,110.5 294.2,110.4 294.9,110.4 294.9,110.8 295.7,110.8 295.7,110.4 296.5,110.4 296.5,110.1 297.3,110.1 297.3,109.9 298.1,109.9 298.1,110.1 298.9,110.1 298.9,110.8 299.7,110.8 299.7,109.9 300.5,109.9 300.5,110.0 301.3,110.0 301.3,109.3 302.1,109.3 302.1,109.3 302.9,109.3 302.9,111.0 303.7,111.0 303.7,110.3 304.5,110.3 304.5,109.7 305.3,109.7 305.3,109.4 306.1,109.4 306.1,109.7 306.9,109.7 306.9,109.6 307.7,109.6 307.7,109.9 308.5,109.9 308.5,109.4 309.3,109.4 309.3,109.7 310.1,109.7 310.1,109.3 310.9,109.3 310.9,109.4 311.7,109.4 311.7,109.3 312.5,109.3 312.5,109.3 313.3,109.3 313.3,109.2 314.1,109.2 314.1,109.5 314.9,109.5 314.9,109.7 315.7,109.7 315.7,110.2 316.5,110.2 316.5,109.9 317.3,109.9 317.3,110.4 318.1,110.4 318.1,109.7 318.8,109.7 318.8,109.7 319.6,109.7 319.6,109.0 320.4,109.0 320.4,109.1 321.2,109.1 321.2,110.0 322.0,110.0 322.0,109.6 322.8,109.6 322.8,109.4 323.6,109.4 323.6,109.5 324.4,109.5 324.4,110.2 325.2,110.2 325.2,109.4 326.0,109.4 326.0,109.7 326.8,109.7 326.8,110.2 327.6,110.2 327.6,109.6 328.4,109.6 328.4,108.8 329.2,108.8 329.2,110.3 330.0,110.3 330.0,110.0"/>
<circle class="nj-charts-json-dot" cx="130.0" cy="147.4" r="3.5"><title>#5285: 3.3&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="130.0" y1="54.0" x2="130.0" y2="142.4"/>
<circle class="nj-theme-dot" cx="130.0" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="130.0" y="50.0" text-anchor="middle">6</text>
<circle class="nj-charts-json-dot" cx="241.6" cy="139.0" r="3.5"><title>#5738: 3.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="241.6" y1="54.0" x2="241.6" y2="134.0"/>
<circle class="nj-theme-dot" cx="241.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="241.6" y="50.0" text-anchor="middle">2</text>
<circle class="nj-charts-json-dot" cx="271.0" cy="131.0" r="3.5"><title>#5878: 4.5&#215;</title></circle>
<circle class="nj-charts-json-dot" cx="276.6" cy="109.6" r="3.5"><title>#5883: 6.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="276.6" y1="54.0" x2="276.6" y2="104.6"/>
<circle class="nj-theme-dot" cx="276.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="276.6" y="50.0" text-anchor="middle">2</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-from_cbor_twitter nj-blog-tl-from_cbor_twitter-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-from_cbor_twitter">from_cbor() twitter: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-from_cbor_twitter-d">from_cbor() twitter: speedup over 3.12.0 at each of 360 commits, ending at 2.8x. Labeled steps, by theme: 1, 4, U, U, 4.</desc>
<text class="nj-charts-panel" x="8" y="18">from_cbor() twitter</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="137" x2="330" y2="137"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="141">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">4&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,209.1 45.6,209.1 45.6,208.2 46.4,208.2 46.4,208.6 47.2,208.6 47.2,208.0 48.0,208.0 48.0,208.4 48.8,208.4 48.8,208.6 49.6,208.6 49.6,208.3 50.4,208.3 50.4,209.1 51.2,209.1 51.2,207.8 52.0,207.8 52.0,208.5 52.8,208.5 52.8,208.6 53.6,208.6 53.6,208.6 54.4,208.6 54.4,207.7 55.2,207.7 55.2,207.1 55.9,207.1 55.9,207.3 56.7,207.3 56.7,206.9 57.5,206.9 57.5,207.1 58.3,207.1 58.3,207.0 59.1,207.0 59.1,207.1 59.9,207.1 59.9,207.1 60.7,207.1 60.7,207.5 61.5,207.5 61.5,207.5 62.3,207.5 62.3,206.9 63.1,206.9 63.1,207.0 63.9,207.0 63.9,206.2 64.7,206.2 64.7,207.1 65.5,207.1 65.5,208.5 66.3,208.5 66.3,208.0 67.1,208.0 67.1,207.8 67.9,207.8 67.9,208.5 68.7,208.5 68.7,207.8 69.5,207.8 69.5,207.0 70.3,207.0 70.3,208.1 71.1,208.1 71.1,208.2 71.9,208.2 71.9,208.6 72.7,208.6 72.7,208.1 73.5,208.1 73.5,207.2 74.3,207.2 74.3,208.3 75.1,208.3 75.1,207.4 75.9,207.4 75.9,207.9 76.7,207.9 76.7,207.7 77.5,207.7 77.5,208.6 78.3,208.6 78.3,207.3 79.1,207.3 79.1,207.9 79.8,207.9 79.8,208.4 80.6,208.4 80.6,208.5 81.4,208.5 81.4,208.0 82.2,208.0 82.2,207.1 83.0,207.1 83.0,208.1 83.8,208.1 83.8,208.1 84.6,208.1 84.6,207.8 85.4,207.8 85.4,207.9 86.2,207.9 86.2,207.9 87.0,207.9 87.0,208.7 87.8,208.7 87.8,208.1 88.6,208.1 88.6,168.9 89.4,168.9 89.4,170.3 90.2,170.3 90.2,169.9 91.0,169.9 91.0,169.0 91.8,169.0 91.8,169.6 92.6,169.6 92.6,169.1 93.4,169.1 93.4,170.1 94.2,170.1 94.2,168.8 95.0,168.8 95.0,167.9 95.8,167.9 95.8,170.4 96.6,170.4 96.6,169.5 97.4,169.5 97.4,169.7 98.2,169.7 98.2,172.9 99.0,172.9 99.0,170.5 99.8,170.5 99.8,170.4 100.6,170.4 100.6,170.1 101.4,170.1 101.4,170.2 102.2,170.2 102.2,170.7 103.0,170.7 103.0,170.5 103.7,170.5 103.7,170.4 104.5,170.4 104.5,171.1 105.3,171.1 105.3,170.2 106.1,170.2 106.1,168.6 106.9,168.6 106.9,168.9 107.7,168.9 107.7,168.8 108.5,168.8 108.5,170.5 109.3,170.5 109.3,169.2 110.1,169.2 110.1,169.8 110.9,169.8 110.9,168.2 111.7,168.2 111.7,168.3 112.5,168.3 112.5,169.9 113.3,169.9 113.3,170.3 114.1,170.3 114.1,170.5 114.9,170.5 114.9,169.2 115.7,169.2 115.7,170.5 116.5,170.5 116.5,170.1 117.3,170.1 117.3,170.0 118.1,170.0 118.1,170.0 118.9,170.0 118.9,169.7 119.7,169.7 119.7,169.9 120.5,169.9 120.5,169.2 121.3,169.2 121.3,169.6 122.1,169.6 122.1,170.0 122.9,170.0 122.9,170.0 123.7,170.0 123.7,170.5 124.5,170.5 124.5,170.8 125.3,170.8 125.3,170.5 126.1,170.5 126.1,170.8 126.9,170.8 126.9,169.2 127.6,169.2 127.6,128.6 128.4,128.6 128.4,121.0 129.2,121.0 129.2,120.5 130.0,120.5 130.0,120.8 130.8,120.8 130.8,120.9 131.6,120.9 131.6,120.2 132.4,120.2 132.4,116.5 133.2,116.5 133.2,117.5 134.0,117.5 134.0,117.4 134.8,117.4 134.8,118.0 135.6,118.0 135.6,118.3 136.4,118.3 136.4,118.0 137.2,118.0 137.2,120.1 138.0,120.1 138.0,118.9 138.8,118.9 138.8,119.6 139.6,119.6 139.6,119.0 140.4,119.0 140.4,120.9 141.2,120.9 141.2,118.6 142.0,118.6 142.0,121.1 142.8,121.1 142.8,120.1 143.6,120.1 143.6,118.4 144.4,118.4 144.4,119.3 145.2,119.3 145.2,119.0 146.0,119.0 146.0,120.2 146.8,120.2 146.8,119.0 147.6,119.0 147.6,119.4 148.4,119.4 148.4,119.8 149.2,119.8 149.2,120.4 150.0,120.4 150.0,120.6 150.8,120.6 150.8,119.6 151.5,119.6 151.5,118.8 152.3,118.8 152.3,118.4 153.1,118.4 153.1,120.2 153.9,120.2 153.9,119.3 154.7,119.3 154.7,119.9 155.5,119.9 155.5,119.6 156.3,119.6 156.3,119.7 157.1,119.7 157.1,119.2 157.9,119.2 157.9,119.5 158.7,119.5 158.7,118.0 159.5,118.0 159.5,150.3 160.3,150.3 160.3,150.5 161.1,150.5 161.1,150.6 161.9,150.6 161.9,151.3 162.7,151.3 162.7,151.4 163.5,151.4 163.5,150.7 164.3,150.7 164.3,152.1 165.1,152.1 165.1,151.8 165.9,151.8 165.9,152.4 166.7,152.4 166.7,150.6 167.5,150.6 167.5,152.8 168.3,152.8 168.3,154.2 169.1,154.2 169.1,152.8 169.9,152.8 169.9,152.9 170.7,152.9 170.7,153.6 171.5,153.6 171.5,151.7 172.3,151.7 172.3,153.8 173.1,153.8 173.1,151.6 173.9,151.6 173.9,152.6 174.7,152.6 174.7,153.5 175.4,153.5 175.4,151.8 176.2,151.8 176.2,152.7 177.0,152.7 177.0,153.6 177.8,153.6 177.8,152.7 178.6,152.7 178.6,152.5 179.4,152.5 179.4,152.7 180.2,152.7 180.2,151.6 181.0,151.6 181.0,153.2 181.8,153.2 181.8,154.6 182.6,154.6 182.6,152.1 183.4,152.1 183.4,152.9 184.2,152.9 184.2,153.9 185.0,153.9 185.0,153.0 185.8,153.0 185.8,152.6 186.6,152.6 186.6,154.0 187.4,154.0 187.4,154.0 188.2,154.0 188.2,154.3 189.0,154.3 189.0,152.5 189.8,152.5 189.8,154.4 190.6,154.4 190.6,154.2 191.4,154.2 191.4,151.8 192.2,151.8 192.2,154.0 193.0,154.0 193.0,153.0 193.8,153.0 193.8,152.2 194.6,152.2 194.6,153.7 195.4,153.7 195.4,153.8 196.2,153.8 196.2,153.9 197.0,153.9 197.0,155.5 197.8,155.5 197.8,153.4 198.6,153.4 198.6,155.4 199.3,155.4 199.3,152.8 200.1,152.8 200.1,154.0 200.9,154.0 200.9,152.3 201.7,152.3 201.7,153.2 202.5,153.2 202.5,153.5 203.3,153.5 203.3,153.6 204.1,153.6 204.1,154.6 204.9,154.6 204.9,152.7 205.7,152.7 205.7,155.4 206.5,155.4 206.5,152.5 207.3,152.5 207.3,153.3 208.1,153.3 208.1,153.3 208.9,153.3 208.9,154.5 209.7,154.5 209.7,152.6 210.5,152.6 210.5,153.0 211.3,153.0 211.3,154.3 212.1,154.3 212.1,122.0 212.9,122.0 212.9,123.3 213.7,123.3 213.7,121.4 214.5,121.4 214.5,122.4 215.3,122.4 215.3,122.6 216.1,122.6 216.1,122.9 216.9,122.9 216.9,123.5 217.7,123.5 217.7,123.0 218.5,123.0 218.5,123.1 219.3,123.1 219.3,123.2 220.1,123.2 220.1,123.3 220.9,123.3 220.9,122.2 221.7,122.2 221.7,123.7 222.5,123.7 222.5,124.3 223.2,124.3 223.2,123.7 224.0,123.7 224.0,123.8 224.8,123.8 224.8,123.1 225.6,123.1 225.6,123.6 226.4,123.6 226.4,123.9 227.2,123.9 227.2,122.7 228.0,122.7 228.0,123.3 228.8,123.3 228.8,123.8 229.6,123.8 229.6,123.0 230.4,123.0 230.4,123.2 231.2,123.2 231.2,122.2 232.0,122.2 232.0,122.9 232.8,122.9 232.8,122.0 233.6,122.0 233.6,121.4 234.4,121.4 234.4,122.1 235.2,122.1 235.2,122.7 236.0,122.7 236.0,122.3 236.8,122.3 236.8,122.5 237.6,122.5 237.6,123.5 238.4,123.5 238.4,124.3 239.2,124.3 239.2,123.8 240.0,123.8 240.0,123.6 240.8,123.6 240.8,123.5 241.6,123.5 241.6,123.2 242.4,123.2 242.4,123.1 243.2,123.1 243.2,122.8 244.0,122.8 244.0,123.9 244.8,123.9 244.8,124.1 245.6,124.1 245.6,124.3 246.4,124.3 246.4,123.9 247.1,123.9 247.1,123.1 247.9,123.1 247.9,121.3 248.7,121.3 248.7,122.2 249.5,122.2 249.5,114.0 250.3,114.0 250.3,112.4 251.1,112.4 251.1,113.8 251.9,113.8 251.9,113.2 252.7,113.2 252.7,113.7 253.5,113.7 253.5,113.4 254.3,113.4 254.3,111.3 255.1,111.3 255.1,111.3 255.9,111.3 255.9,113.3 256.7,113.3 256.7,113.6 257.5,113.6 257.5,112.9 258.3,112.9 258.3,112.5 259.1,112.5 259.1,112.4 259.9,112.4 259.9,113.3 260.7,113.3 260.7,112.7 261.5,112.7 261.5,112.9 262.3,112.9 262.3,112.1 263.1,112.1 263.1,112.5 263.9,112.5 263.9,113.2 264.7,113.2 264.7,113.3 265.5,113.3 265.5,112.4 266.3,112.4 266.3,113.0 267.1,113.0 267.1,112.9 267.9,112.9 267.9,112.6 268.7,112.6 268.7,113.5 269.5,113.5 269.5,113.3 270.3,113.3 270.3,109.2 271.0,109.2 271.0,109.0 271.8,109.0 271.8,109.1 272.6,109.1 272.6,108.5 273.4,108.5 273.4,107.5 274.2,107.5 274.2,108.0 275.0,108.0 275.0,109.2 275.8,109.2 275.8,109.2 276.6,109.2 276.6,109.1 277.4,109.1 277.4,109.5 278.2,109.5 278.2,109.1 279.0,109.1 279.0,109.2 279.8,109.2 279.8,108.5 280.6,108.5 280.6,109.0 281.4,109.0 281.4,109.2 282.2,109.2 282.2,108.7 283.0,108.7 283.0,108.7 283.8,108.7 283.8,109.2 284.6,109.2 284.6,106.9 285.4,106.9 285.4,108.5 286.2,108.5 286.2,109.2 287.0,109.2 287.0,109.1 287.8,109.1 287.8,109.6 288.6,109.6 288.6,109.0 289.4,109.0 289.4,108.3 290.2,108.3 290.2,109.3 291.0,109.3 291.0,109.7 291.8,109.7 291.8,108.4 292.6,108.4 292.6,109.0 293.4,109.0 293.4,109.4 294.2,109.4 294.2,109.8 294.9,109.8 294.9,108.8 295.7,108.8 295.7,108.8 296.5,108.8 296.5,111.4 297.3,111.4 297.3,109.4 298.1,109.4 298.1,109.6 298.9,109.6 298.9,110.5 299.7,110.5 299.7,109.6 300.5,109.6 300.5,109.5 301.3,109.5 301.3,110.1 302.1,110.1 302.1,109.1 302.9,109.1 302.9,111.2 303.7,111.2 303.7,110.0 304.5,110.0 304.5,109.4 305.3,109.4 305.3,109.8 306.1,109.8 306.1,109.5 306.9,109.5 306.9,110.3 307.7,110.3 307.7,109.5 308.5,109.5 308.5,109.3 309.3,109.3 309.3,111.2 310.1,111.2 310.1,108.6 310.9,108.6 310.9,109.8 311.7,109.8 311.7,108.4 312.5,108.4 312.5,108.2 313.3,108.2 313.3,107.7 314.1,107.7 314.1,108.7 314.9,108.7 314.9,108.6 315.7,108.6 315.7,109.9 316.5,109.9 316.5,108.8 317.3,108.8 317.3,110.2 318.1,110.2 318.1,109.3 318.8,109.3 318.8,109.3 319.6,109.3 319.6,107.7 320.4,107.7 320.4,108.1 321.2,108.1 321.2,110.8 322.0,110.8 322.0,108.2 322.8,108.2 322.8,109.9 323.6,109.9 323.6,109.0 324.4,109.0 324.4,108.0 325.2,108.0 325.2,109.3 326.0,109.3 326.0,108.9 326.8,108.9 326.8,108.9 327.6,108.9 327.6,107.7 328.4,107.7 328.4,101.8 329.2,101.8 329.2,102.8 330.0,102.8 330.0,102.3"/>
<circle class="nj-charts-json-dot" cx="88.6" cy="168.9" r="3.5"><title>#5233: 1.47&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="88.6" y1="54.0" x2="88.6" y2="163.9"/>
<circle class="nj-theme-dot" cx="88.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="88.6" y="50.0" text-anchor="middle">1</text>
<circle class="nj-charts-json-dot" cx="127.6" cy="128.6" r="3.5"><title>#5501: 2.2&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="127.6" y1="54.0" x2="127.6" y2="123.6"/>
<circle class="nj-theme-dot" cx="127.6" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="127.6" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="159.5" cy="150.3" r="3.5"><title>#5185: 1.76&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="159.5" y1="54.0" x2="159.5" y2="145.3"/>
<circle class="nj-theme-dot nj-theme-dot--other" cx="159.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="159.5" y="50.0" text-anchor="middle">U</text>
<circle class="nj-charts-json-dot" cx="212.1" cy="122.0" r="3.5"><title>#5746: 2.3&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="212.1" y1="54.0" x2="212.1" y2="117.0"/>
<circle class="nj-theme-dot nj-theme-dot--other" cx="212.1" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="212.1" y="50.0" text-anchor="middle">U</text>
<circle class="nj-charts-json-dot" cx="328.4" cy="101.8" r="3.5"><title>#6028: 2.8&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="328.4" y1="54.0" x2="328.4" y2="96.8"/>
<circle class="nj-theme-dot" cx="322.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="322.5" y="50.0" text-anchor="middle">4</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
</div>

<p class="nj-caption" markdown>Speedup over 3.12.0 after each of the 358 commits that changed the headers up to November
7, from 3.12.0 (left) to 3.13.0 (right). More is better; each point is the median of 4 runs of one build, taken in
random order (with 4 runs, the mean of the two middle ones). The badges are theme numbers; "U" is a UTF-8 check that
came and went. The other four workloads, and every labeled step with its pull request and size, are in [Appendix
C](#c-the-timeline).</p>

A few things stand out. A percentage for a step is relative to the time just before that step, not to the time of
3.12.0:

- **There is no single big step.** Parsing `citm_catalog.json` got faster in about six visible steps. The largest
  removed a buffer that only error messages read, which alone saved 35% of the time. The next ones added the fast paths
  for contiguous input, derived positions only on error, and skipped indentation eight bytes at a time; most other
  changes moved it by a few percent.
- **Writing had a few large steps.** `dump()` of `twitter.json` lost 70% of its time in one change (a write buffer and
  bulk string copies), and `dump()` of `canada.json` 65% in another (Żmij).
- **Regressions happen in between.** A UTF-8 check of every text string in the binary readers, byte by byte, made
  `from_cbor()` of `twitter.json` 37% slower for 66 commits, until the readers were made lenient again by default, as in
  3.12.0, with the check as an option. That decision was about the format specifications, which don't require a decoder
  to check, not about speed. The cost went with it. It never shipped in a release.
- **The input decides how big a step is.** Removing the error-message buffer measured 8% on the benchmark of its pull
  request; on the indented `citm_catalog.json` it saved 35%, because every space of the indentation went through that
  buffer.

## <span class="nj-theme">1</span> Specialize for each input source { #theme-1 }

This is the function the 3.12.0 lexer called for **every** byte of input:

```cpp
char_int_type get()
{
    ++position.chars_read_total;
    ++position.chars_read_current_line;

    if (next_unget)
    {
        // just reset the next_unget variable and work with current
        next_unget = false;
    }
    else
    {
        current = ia.get_character();
    }

    if (JSON_HEDLEY_LIKELY(current != char_traits<char_type>::eof()))
    {
        token_string.push_back(char_traits<char_type>::to_char_type(current));
    }

    if (current == '\n')
    {
        ++position.lines_read;
        position.chars_read_current_line = 0;
    }

    return current;
}
```

<p class="nj-code-caption" markdown>The 3.12.0 lexer's `get()`, called for every byte of input.</p>

Two counters in memory, a branch for a pending `unget()`, a call into the input adapter, a `push_back()` into a buffer
that only an error message reads, and a branch for line breaks. The counters are members of the lexer, so the compiler
has to load, add, and store them for every byte. A string or a number then copied each byte a second time into their
token buffer. That is a clean design: one interface works for a `std::string`, an `std::istream`, a `FILE*`, a pair of
iterators over a `std::list<char>`, or a user's own adapter. But it makes every input pay for the most limited one.

3.13.0 has a dedicated reader for each kind of input and picks it at compile time:

```mermaid
flowchart LR
    src[/"input"/] --> q{{"what is it?"}}
    q -->|"std::string, std::vector,<br>their iterators, pointers,<br>contiguous ranges"| c["contiguous:<br>scan the whole buffer"]
    q -->|"std::istream"| w["window:<br>scan the streambuf's get area"]
    q -->|"FILE*"| f["window:<br>scan the FILE's buffer"]
    q -->|"other iterators,<br>user adapters"| b["byte at a time"]
```

<p class="nj-caption" markdown>The four kinds of input the lexer distinguishes in 3.13.0. Everything on the fast paths
falls back to the byte path on anything unusual, so the result and the error messages stay the same. The `FILE*`
window needs glibc or Apple's C library; elsewhere, a `FILE*` is read one character at a time with one lock per
parse.</p>

### Detecting the input in C++11

An input adapter can declare what it supports as static members (`supports_seek`, `supports_bulk_scan`, and a few more).
The lexer detects them with the detection idiom, so a user's adapter that declares nothing keeps the byte path:

```cpp
template<typename A> using detect_supports_seek = decltype(A::supports_seek);
template<typename A>
constexpr bool input_adapter_supports_seek(std::true_type) { return A::supports_seek; }
template<typename A>
constexpr bool input_adapter_supports_seek(std::false_type) { return false; }

static constexpr bool seekable = input_adapter_supports_seek<InputAdapterType>(
    is_detected<detect_supports_seek, InputAdapterType> {});
static constexpr bool lazy_position = seekable;
```

<p class="nj-code-caption" markdown>Detecting a static member of the input adapter with the detection idiom: an adapter
that doesn't declare `supports_seek` is not seekable.</p>

Without `if constexpr`, the flags select overloads by tag dispatch, `f(std::integral_constant<bool, lazy_position>{})`,
which also keeps MSVC from warning about constant conditions. `get()` still looks like the old one, but its position and
token bookkeeping are now calls. For an adapter that can seek, their `std::true_type` overloads are empty and cost
nothing, because the position and the text of a token are derived only when an error message needs them (theme
<a class="nj-theme" href="#theme-4" title="theme 4">4</a>). For a `std::string`, what remains is the branch on
`next_unget` and the adapter's bounds check and pointer increment. For the most common calls, not even that remains:
they don't use the lexer at all ([One loop instead of two](#one-loop-instead-of-two)).

### Contiguous input

Containers with `data()` and `size()` over single-byte elements now become a pointer range in every C++ standard, not
only with C++20's contiguous iterators. `data()` and `size()` alone would be duck typing, so the trait also requires the
container's `value_type` to be the element type behind `data()`. A type whose `size()` counts something else keeps the
iterator path: slower, but correct. On a pointer range, the strings, the numbers and the indentation after a line break
are scanned in bulk (themes <a class="nj-theme" href="#theme-2" title="theme 2">2</a> and
<a class="nj-theme" href="#theme-3" title="theme 3">3</a>). Every fast path defers to the byte path on anything
malformed, so error messages and byte positions stay the same, with one deliberate correction (the column after a number
at the end of a line). [Appendix J](#j-validation) describes how that was checked.

A pair of iterators is harder. Before C++20, `s.begin()` and `s.end()` of a `std::string` can't be told from the
iterators of any other random-access container, so `json::parse(s.begin(), s.end())` was read one character at a time,
while `json::parse(s)` got all the bulk scans. The library now matches the iterator types of `std::string` and of a
`std::vector` of one-byte integers exactly, and turns the pair into the pointer range it covers. That made
`parse(s.begin(), s.end())` 1.7–2.0× as fast on the M1, and `accept()` 2.7–3.1×.

### One loop instead of two

Even on a pointer range, the parser and the lexer still talked through an interface: the parser asks for a token, the
lexer finds it and hands it over, and the parser dispatches on its type. The lexer's state, the current character, a
pending `unget()`, and where the token starts, lives in members, so it goes through memory on every token. After all of
the above, `json::accept()` of `twitter.json` still took 2.8× as long as `json_document::accept()` (theme
<a class="nj-theme" href="#theme-8" title="theme 8">8</a>), which reads the same bytes.

[yyjson](https://github.com/ibireme/yyjson)'s reader shows the alternative: one function that holds the input in a
local pointer and in which the grammar, the whitespace and the tokens are one loop. After a `:`, it tests for the
characters that can start a value right there, instead of returning a token type and dispatching on it. 3.13.0 adds
such a parser for input in one block of memory, `contiguous_parser`. Its stack of open arrays and objects is a 64-bit
word with one bit per level, so the kind of the enclosing container is a shift away and stays in a register; every 64
levels, the word is pushed to a vector. It doesn't build values itself: it drives the library's own SAX handlers, so
`parse()` builds the same `json` with the same code as before. It is used by `parse()` without a callback, by
`accept()`, and by `sax_parse()` with the user's own handler, each with the default options; everything else keeps the
old parser.

The hard part was the errors. A second parser would have to produce the same exception, message and position for
every malformed input, a large surface for small differences. So it doesn't report errors at all. It stops at the
token the old parser would reject, before it reports that token to the handler, and the old parser runs again on the
same input to report the error. `parse()` gives it a handler that only reports, and `sax_parse()` one that forwards
only `parse_error()` to the user's handler, so that no event arrives twice. An error at the end of a large input costs
`parse()` about 1.2× as much as before; valid input costs nothing extra.

On the M1, `accept()` got 1.6–2.0× as fast, `sax_parse()` 1.4–1.5×, and `parse()` 10–16% faster, about the same with
GCC and Clang on x86-64. In `accept()`, which needs no values, the parser also skips the digits of a number without
computing its value, except for the rare float whose exponent may reach the largest `double`: another 16% on
`canada.json`. The cost is about 1,000 lines of header, and a translation unit that parses a string and dumps it
compiles 3% slower at `-O0` and 9% at `-O2`.

### Streams

An `std::istream` already has a buffer: the get area of its `streambuf`, `gptr()` to `egptr()`. The lexer now scans that
window in bulk and keeps the current token as a pointer into it. Those are protected members of `std::streambuf`, and
reaching them takes neither a cast nor a derived object:

```cpp
struct streambuf_access : std::streambuf
{
    static const char* get_ptr(std::streambuf* s) { return (s->*(&streambuf_access::gptr))(); }
    static const char* get_end(std::streambuf* s) { return (s->*(&streambuf_access::egptr))(); }
    static void bump(std::streambuf* s, int n)    { (s->*(&streambuf_access::gbump))(n); }
};
```

<p class="nj-code-caption" markdown>Reaching the protected get area of any `std::streambuf` through pointers to members,
without a cast.</p>

A derived class may name a protected member of its base in a pointer to member, as long as it qualifies the name with
its own class. The resulting pointer has the type `char* (std::streambuf::*)() const`, and access is checked when the
name is used, not when the pointer is called, so it works on any `std::streambuf*`. The common alternative,
`static_cast<streambuf_access*>(sb)->gptr()`, is undefined behavior, because the object is not a `streambuf_access`.

Before the stream refills its get area, the adapter appends the part of the current token that is in it to a carry
buffer; only an error message ever reads the token text back. Nothing is read ahead: the adapter advances `gptr()` by
exactly what the lexer consumes, so the stream is left where it was before. On an M1 Max, parsing from an
`std::ifstream` took 1.8–2.5× as long as reading the file into a string and parsing that, in the pull request's
measurement before the change, and 9–16% longer after it. Since then, parsing a string got faster still, because the
fused parser of [One loop instead of two](#one-loop-instead-of-two) needs input in one block of memory, so a stream now
takes 25–38% longer than the string again (the file read with one `read()`, parsing `twitter.json`,
`citm_catalog.json`, and `canada.json`).

### `FILE*`

`std::fgetc` locks the `FILE` on every call. 3.13.0 locks it once per parse (`flockfile`, then `getc_unlocked`;
`_lock_file` and `_fgetc_nolock` with the Microsoft runtime). `flockfile` is recursive, so the binary readers' `fread()`
and a SAX handler's own `ftell()` keep working. Whereas parsing `citm_catalog.json` from a `FILE*` got 4.4× as fast on
macOS in the pull request's measurement, with glibc it got only 1.1–1.3× as fast, because glibc's per-call locking is
already cheap.

That still left a call per character, while a stream had its get area scanned in bulk. But a `FILE` has a buffer too,
and `getc_unlocked()` is a macro that reads it: glibc's compares `_IO_read_ptr` with `_IO_read_end`, Apple's counts
down `_r` and advances `_p`. The adapter now reads those same fields and offers the lexer the rest of the buffer as a
window, as for a stream. It consumes exactly the characters `getc_unlocked()` would have returned, so the file is
left where it was before, and when the C library is about to refill the buffer, the part of the current token in it is
kept for error messages. The idea is gnulib's
[`freadptr()`](https://github.com/coreutils/gnulib/blob/master/lib/freadptr.c), which knows these fields for many C
libraries. Parsing from a `FILE*` got another 2.0–2.6× faster on the M1 and 1.7–2.2× with glibc on x86-64, and
`accept()` 2.9–4.4×; it is now about as fast as parsing from an `std::ifstream`. uClibc
defines `__GLIBC__` but has other fields, so it is excluded, and other C libraries keep reading one character at a
time.

Two details: MemorySanitizer builds keep `fgetc`, because glibc's inline `getc_unlocked` reads a buffer that
uninstrumented glibc filled. And a SAX handler that waits for another thread using the same `FILE` now deadlocks, as the
documentation says. Both paths can be switched off, with
[`JSON_DISABLE_STREAM_BULK_SCAN`](../../api/macros/json_disable_stream_bulk_scan.md) and
[`JSON_DISABLE_UNLOCKED_FILE_IO`](../../api/macros/json_disable_unlocked_file_io.md); the second turns the `FILE`
window off as well, as it needs the lock for the whole parse.

## <span class="nj-theme">2</span> Work on words, not bytes { #theme-2 }

The core of a JSON lexer is "copy bytes until something interesting happens". Theme 1 gave it ranges of bytes. This
theme reads them a word at a time.

### Eight bytes in a word

In a string, the interesting bytes are the closing quote, a backslash, a control character, and anything above 0x7F
(UTF-8). This test checks eight bytes at once with ordinary 64-bit arithmetic:

```cpp
// return a word whose high bit is set in every byte of v that needs
// individual handling; zero if all 8 bytes can be copied as they are
inline std::uint64_t swar_string_special(std::uint64_t v) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'
    const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\'
    const std::uint64_t has_quote     = (q - ones) & ~q & high;
    const std::uint64_t has_backslash = (b - ones) & ~b & high;
    const std::uint64_t has_control   = (v - 0x2020202020202020ull) & ~v & high; // < 0x20
    const std::uint64_t has_non_ascii = v & high;                                // >= 0x80
    return has_quote | has_backslash | has_control | has_non_ascii;
}
```

<p class="nj-code-caption" markdown>The eight-byte test of the string scanner, in portable C++11.</p>

XOR with the quote turns every quote byte into zero, and `(x - 0x01…01) & ~x & 0x80…80` sets the high bit of the bytes
that were zero: the "determine if a word has a zero byte" trick from Sean Eron Anderson's [Bit Twiddling
Hacks](https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord). The subtraction's borrow runs only upwards, so
it can flag a byte *after* a real hit, but never one before it: the lowest flag is always right, and the number of
trailing zero bits divided by eight is the index of the first special byte.

The code above is the readable form, and it does more work than it needs to. The `& ~x` of the zero-byte test only
keeps bytes from 0x80 out of the result, and `has_non_ascii` flags exactly those bytes anyway. So all three `& ~x`
terms can go, and the whole test becomes one expression:

```cpp
return ((q - ones) | (b - ones) | (v - 0x2020202020202020ull) | v) & high;
```

<p class="nj-code-caption" markdown>The same test without the redundant `& ~x` terms.</p>

Clang finds this reduction on its own; GCC doesn't, and emitted 24 instructions per word instead of 16. With GCC on
x86-64, writing it out made validating `twitter.json` and `citm_catalog.json` 5–7% faster and `dump()` 2–3%. The
masks of both forms are the same for every pair of adjacent byte values and for 1.3 billion random words.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--swar" viewBox="0 0 640 312" role="img" aria-labelledby="nj-blog-swar nj-blog-swar-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-swar">Finding the end of a run of ordinary string characters eight bytes at a time</title>
<desc id="nj-blog-swar-d">The eight bytes w, i, t, t, e, r, quote and comma are loaded as one word. The test sets the high bit only in byte 6, the quote. Counting trailing zero bits gives 55, divided by eight gives 6: bytes 0 to 5 are copied at once, then the quote ends the string.</desc>
<text class="fg-h" x="40" y="20">eight input bytes, loaded as one 64-bit word (byte 0 is the lowest)</text>
<rect class="fg-cell" x="40" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="72" y="60" text-anchor="middle">w</text>
<text class="nj-charts-tick" x="72" y="92">0x77</text>
<text class="nj-charts-tick" x="72" y="108">byte 0</text>
<rect class="fg-cell" x="110" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="142" y="60" text-anchor="middle">i</text>
<text class="nj-charts-tick" x="142" y="92">0x69</text>
<text class="nj-charts-tick" x="142" y="108">byte 1</text>
<rect class="fg-cell" x="180" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="212" y="60" text-anchor="middle">t</text>
<text class="nj-charts-tick" x="212" y="92">0x74</text>
<text class="nj-charts-tick" x="212" y="108">byte 2</text>
<rect class="fg-cell" x="250" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="282" y="60" text-anchor="middle">t</text>
<text class="nj-charts-tick" x="282" y="92">0x74</text>
<text class="nj-charts-tick" x="282" y="108">byte 3</text>
<rect class="fg-cell" x="320" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="352" y="60" text-anchor="middle">e</text>
<text class="nj-charts-tick" x="352" y="92">0x65</text>
<text class="nj-charts-tick" x="352" y="108">byte 4</text>
<rect class="fg-cell" x="390" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="422" y="60" text-anchor="middle">r</text>
<text class="nj-charts-tick" x="422" y="92">0x72</text>
<text class="nj-charts-tick" x="422" y="108">byte 5</text>
<rect class="fg-cell" x="460" y="34" width="64" height="40" rx="4"/>
<rect class="nj-charts-c2" fill-opacity=".25" x="460" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="492" y="60" text-anchor="middle">&quot;</text>
<text class="nj-charts-tick" x="492" y="92">0x22</text>
<text class="nj-charts-tick" x="492" y="108">byte 6</text>
<rect class="fg-cell" x="530" y="34" width="64" height="40" rx="4"/>
<text class="fg-code" x="562" y="60" text-anchor="middle">,</text>
<text class="nj-charts-tick" x="562" y="92">0x2C</text>
<text class="nj-charts-tick" x="562" y="108">byte 7</text>
<text class="fg-h" x="40" y="132">swar_string_special(): the high bit of each byte that needs handling</text>
<rect class="fg-cell" x="40" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="72" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="110" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="142" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="180" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="212" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="250" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="282" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="320" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="352" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="390" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="422" y="169" text-anchor="middle">0x00</text>
<rect class="fg-cell" x="460" y="146" width="64" height="34" rx="4"/>
<rect class="nj-charts-c2" fill-opacity=".25" x="460" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="492" y="169" text-anchor="middle">0x80</text>
<rect class="fg-cell" x="530" y="146" width="64" height="34" rx="4"/>
<text class="fg-code" x="562" y="169" text-anchor="middle">0x00</text>
<text class="fg-code" x="40" y="216">count_trailing_zeros(0x0080000000000000) = 55</text>
<text class="fg-code" x="40" y="242">55 / 8 = 6: copy bytes 0 to 5 in one go, then handle the quote</text>
<text class="fg-note fg-note--l" x="40" y="272">No branch per byte: a few subtractions, ANDs and ORs per word,</text>
<text class="fg-note fg-note--l" x="40" y="290">then one count of trailing zeros.</text>
</svg>

</div>

<p class="nj-caption" markdown>`swar_string_special()` on the last eight bytes of `"twitter",`: one word in, one flag
out, and the count of trailing zero bits says how many bytes can be copied before the quote.</p>

Two details make this portable C++11. The word is loaded with `std::memcpy`, which compilers turn into one load and
which, unlike a `reinterpret_cast`, doesn't break the aliasing rules. And the load always produces the bytes in
little-endian order, so the first byte of the text is the lowest byte of the word everywhere; a big-endian target
assembles the word from bytes, which compilers fold into a load and a byte swap. Every loop checks that eight bytes
remain before it loads, and finishes the remaining one to seven bytes one at a time, so nothing is read past the
input.

The same kind of word test now runs in several places:

- **Strings in the lexer,** including runs of well-formed multi-byte UTF-8, which are validated one sequence after the
  other without going back to the byte loop.
- **Numbers,** eight digits per step (theme <a class="nj-theme" href="#theme-3" title="theme 3">3</a>).
- **Indentation.** After a newline, `word ^ 0x2020…20` is zero for eight spaces; the first non-zero byte ends the
  indentation, and its trailing-zero count says how many spaces of the last word to skip as well. The idea is from
  [Glaze](https://github.com/stephenberry/glaze)'s `skip_matching_ws`, which compares with the previous line's
  indentation; comparing with spaces needs no state and works for any indentation width. A version that skipped only
  whole words validated 5–12% slower and gave nothing on two-space indentation, where the runs are often shorter than a
  word. With four-space indentation, validating `citm_catalog.json` got 22–30% faster.
- **[`dump()`](../../api/basic_json/dump.md),** for runs of characters that need no escaping, with and without
  [`ensure_ascii`](../../api/basic_json/dump.md#parameters).
- **The binary formats,** for the zero byte that ends a BSON key, and for the UTF-8 check of strings with
  `error_handler_t::strict`. On the M1, reading `canada.json` from BSON got 14% faster, and writing `twitter.json` as
  UTF-8-checked CBOR 14%.

### 16 bytes with SSE2 and NEON

Where a vector unit is part of the baseline instruction set (SSE2 on x86-64, NEON on 64-bit Arm), the string paths take
16 bytes per step. Three details are worth repeating. A signed comparison `byte < 0x20` catches control characters
*and* every byte from 0x80, because those are negative as `int8_t`. Flipping bit 1 first folds the quote into that
comparison too: `c ^ 2` maps 0x00–0x1F onto themselves and the quote (0x22) onto 0x20, keeps the bytes from 0x80
negative, and maps every other ASCII byte to 33 or more. So `(int8_t)(c ^ 2) < 33` finds three of the four classes of
bytes, and only the backslash needs a comparison of its own (Daniel Lemire, ["Detect control characters, quotes and
backslashes efficiently using
SWAR"](https://lemire.me/blog/2025/04/13/detect-control-characters-quotes-and-backslashes-efficiently-using-swar/),
2025; ruby/json uses the same trick in its SIMD scan). Neither GCC nor Clang finds this one on its own. And NEON has no
equivalent of x86's `pmovmskb`, which turns a vector of comparison results into a bit mask. The usual replacement, by
[Danila
Kutenin](https://developer.arm.com/community/arm-community-blogs/b/servers-and-cloud-computing-blog/posts/porting-x86-vector-bitmask-optimizations-to-arm-neon),
shifts each 16-bit lane right by four and narrows it to eight bits, which leaves four bits per input byte in a 64-bit
integer:

```cpp
while (e - p >= 16)
{
    const uint8x16_t in = vld1q_u8(p);
    // the backslash, and (c ^ 2) < 33 as int8_t for the quote, the control
    // characters and the bytes from 0x80
    const uint8x16_t special = vorrq_u8(vceqq_u8(in, vdupq_n_u8('\\')),
                                        vcltq_s8(vreinterpretq_s8_u8(veorq_u8(in, vdupq_n_u8(2))),
                                                 vdupq_n_s8(33)));
    // each byte of special is 0x00 or 0xFF; shifting each 16-bit lane right by 4 and
    // keeping its low byte leaves 4 bits per input byte
    const uint8x8_t nibbles = vshrn_n_u16(vreinterpretq_u16_u8(special), 4);
    const std::uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(nibbles), 0);
    if (bits != 0)
    {
        return p + (count_trailing_zeros(bits) >> 2u);   // four bits per byte
    }
    p += 16;
}
```

<p class="nj-code-caption" markdown>The NEON string scan: two comparisons for four classes of bytes, and a narrowing
shift in place of `pmovmskb`.</p>

On `twitter.json`, the vector scan made `json::parse()` 5% faster with Clang and 9% with GCC on an M1 Max; on long
strings, 19–24%. It did not win from the first byte. On the M1, starting with NEON made short strings 3–4% slower and
the rest of the lexer bigger. So ARM runs four 8-byte words first and keeps the vector loop out of line, while x86-64
runs one word first. Inlining the vector code into the lexer cost 5% of validating `jeopardy.json` on the M1, although
no string of that file is long enough to reach it: the scan function, which runs once per token, saved more registers
and needed a stack slot.

[`json_document`](../../features/json_view/index.md), the new document type of `json_view.hpp`, also skips the digits after a
decimal point 16 bytes at a time with SSE2: a compare and a bit mask instead of a branch per digit, about 33% of the
instructions for a 12-digit fraction. Parsing `canada.json` got 22% faster on x86-64, a file of 10,000 floats 28–32%.

One row got slower: with GCC 16, `citm_catalog.json` took 8% longer with the same number of instructions, because more
of its hot jumps now crossed a 32-byte boundary. The microcode fix for Intel's JCC erratum makes that slow on our
server. Assembling with `-Wa,-mbranches-within-32B-boundaries` shrinks the loss to about 4%, but a header-only library
can't choose the assembler flags of the programs that include it, so we left the code as it is, and all numbers in this
post are measured without that flag.

### Validating UTF-8 16 bytes at a time

Validating UTF-8 16 bytes at a time uses [simdjson](https://github.com/simdjson/simdjson)'s "lookup4" algorithm ([Keiser
and Lemire, 2021](https://arxiv.org/abs/2010.03090)): three 16-entry tables, indexed by nibbles of a byte and of the
byte before it, each give the set of errors that nibble allows, and a pair of bytes is invalid if all three sets share
an error. It needs `pshufb`, which is SSSE3 and not part of baseline x86-64. The function is compiled with
`__attribute__((target("ssse3")))`, out of line, and called only if `cpuid` says so. The result of that query is cached
in a constant-initialized `static std::atomic<int>`, so that neither a guarded local static nor a global constructor is
needed; threads that ask at the same time all store the same answer. On an error, the code backs up to the start of the
sequence and lets the byte path produce the error message. [`JSON_NO_SIMD`](../../api/macros/json_no_simd.md) turns all
vector code off.

### Short strings

Short strings are a different problem. Most keys and many values are short: `citm_catalog.json` averages 8 bytes per
string and `jeopardy.json` 14. For them, setting up a scan costs more than the scan. The first step took the idea of
[SQLite](https://sqlite.org/src/file/src/json.c)'s `jsonAppendString()`: check each byte of a string of up to 32 bytes
against a 256-entry table of bytes that can be written unchanged, and copy the string in one go if they all pass. 32
bytes was the best threshold on the M1; 16 gained less, and 64 lost again. The second step replaced the table, where
SSE2 or NEON is available, with overlapping loads, the trick that `memcpy` implementations such as glibc's use for short
copies:

```cpp
// 16 <= n <= 32: two loads that overlap in the middle cover the whole string
const uint8x16_t a = vld1q_u8(p);
const uint8x16_t b = vld1q_u8(p + n - 16);
const uint8x16_t special = /* '"', '\\', < 0x20 or 0x7F, in a or in b */;
if (vmaxvq_u8(special) != 0)
{
    return false;          // nothing has been written yet; take the general path
}
vst1q_u8(d, a);
vst1q_u8(d + n - 16, b);   // the two stores overlap too, with the same bytes
```

<p class="nj-code-caption" markdown>Writing a string of 16–32 bytes with two overlapping loads and stores (NEON).</p>

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--swar" viewBox="0 0 640 294" role="img" aria-labelledby="nj-blog-overlap nj-blog-overlap-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-overlap">Writing an 18-byte string with two overlapping 16-byte loads and stores</title>
<desc id="nj-blog-overlap-d">The 18 bytes of profile_link_color. Load a covers bytes 0 to 15, load b covers bytes 2 to 17, so bytes 2 to 15 are in both. Neither contains a byte that needs escaping, so a is stored at the destination and b 2 bytes later; the second store writes bytes 2 to 15 again with the same values. This works for any length from 16 to 32 bytes without a loop.</desc>
<text class="fg-h" x="40" y="20">a string of n = 18 bytes: too long for one 16-byte vector, too short for a loop</text>
<rect class="fg-cell" x="40" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="53.5" y="58" text-anchor="middle">p</text>
<rect class="fg-cell" x="71" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="84.5" y="58" text-anchor="middle">r</text>
<rect class="fg-cell" x="102" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="102" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="115.5" y="58" text-anchor="middle">o</text>
<rect class="fg-cell" x="133" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="133" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="146.5" y="58" text-anchor="middle">f</text>
<rect class="fg-cell" x="164" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="164" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="177.5" y="58" text-anchor="middle">i</text>
<rect class="fg-cell" x="195" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="195" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="208.5" y="58" text-anchor="middle">l</text>
<rect class="fg-cell" x="226" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="226" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="239.5" y="58" text-anchor="middle">e</text>
<rect class="fg-cell" x="257" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="257" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="270.5" y="58" text-anchor="middle">&#95;</text>
<rect class="fg-cell" x="288" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="288" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="301.5" y="58" text-anchor="middle">l</text>
<rect class="fg-cell" x="319" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="319" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="332.5" y="58" text-anchor="middle">i</text>
<rect class="fg-cell" x="350" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="350" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="363.5" y="58" text-anchor="middle">n</text>
<rect class="fg-cell" x="381" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="381" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="394.5" y="58" text-anchor="middle">k</text>
<rect class="fg-cell" x="412" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="412" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="425.5" y="58" text-anchor="middle">&#95;</text>
<rect class="fg-cell" x="443" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="443" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="456.5" y="58" text-anchor="middle">c</text>
<rect class="fg-cell" x="474" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="474" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="487.5" y="58" text-anchor="middle">o</text>
<rect class="fg-cell" x="505" y="34" width="27" height="36" rx="4"/>
<rect class="nj-charts-c3" fill-opacity=".3" x="505" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="518.5" y="58" text-anchor="middle">l</text>
<rect class="fg-cell" x="536" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="549.5" y="58" text-anchor="middle">o</text>
<rect class="fg-cell" x="567" y="34" width="27" height="36" rx="4"/>
<text class="fg-code" x="580.5" y="58" text-anchor="middle">r</text>
<text class="nj-charts-tick" x="53.5" y="86">0</text>
<text class="nj-charts-tick" x="115.5" y="86">2</text>
<text class="nj-charts-tick" x="518.5" y="86">15</text>
<text class="nj-charts-tick" x="580.5" y="86">17</text>
<rect class="nj-charts-c1" fill-opacity=".22" x="40" y="100" width="492" height="22" rx="4"/>
<rect class="nj-charts-c1" x="40" y="100" width="4" height="22" rx="2"/>
<rect class="nj-charts-c1" x="528" y="100" width="4" height="22" rx="2"/>
<text class="fg-code" x="286" y="116" text-anchor="middle" style="font-size:14px">a = load 16 bytes at p</text>
<rect class="nj-charts-c2" fill-opacity=".22" x="102" y="130" width="492" height="22" rx="4"/>
<rect class="nj-charts-c2" x="102" y="130" width="4" height="22" rx="2"/>
<rect class="nj-charts-c2" x="590" y="130" width="4" height="22" rx="2"/>
<text class="fg-code" x="348" y="146" text-anchor="middle" style="font-size:14px">b = load 16 bytes at p + n &#8722; 16</text>
<text class="fg-note fg-note--l" x="40" y="182">Both loads lie inside the string, and together they cover all of it; bytes 2 to 15 are in both.</text>
<text class="fg-note fg-note--l" x="40" y="204">Test a and b for a quote, a backslash, a control character or 0x7F: none, so write</text>
<text class="fg-code" x="40" y="234">store a at d, store b at d + n &#8722; 16</text>
<text class="fg-note fg-note--l" x="40" y="262">The second store writes bytes 2 to 15 again, with the same values. For any n from 16 to 32:</text>
<text class="fg-note fg-note--l" x="40" y="280">two loads, one test, two stores, no loop and no branch on the length.</text>
</svg>

</div>

<p class="nj-caption" markdown>The code above on `profile_link_color`, a key of `twitter.json`.</p>

On `twitter.json`, this cut the instructions of `dump()` by 21%. Shorter strings use the same trick with two overlapping
8-, 4-, or 2-byte loads, so no `memcpy` with a length known only at run time is left.

### Escapes from a table

When the scanner stops at a quote, a backslash, or a control character, the writer copies its escape sequence from a
table of 8-byte rows, padded with zeros, with the length in the last byte:

```cpp
{{'\\', 'u', '0', '0', '0', '0', 0, 6}},   // 0x00
{{'\\', 'n', 0, 0, 0, 0, 0, 2}},           // 0x0A
{{'\\', '"', 0, 0, 0, 0, 0, 2}},           // 0x22

std::memcpy(write_buffer.data() + write_buffer_pos, escape.data(), 8);   // always 8 bytes
write_buffer_pos += escape[7];                                         // keep only the real length
```

<p class="nj-code-caption" markdown>Three rows of the escape table, and how a row is written: always 8 bytes, then the
real length.</p>

One 8-byte store and one add, with no branch on the length; the padding lies behind the write position and is
overwritten by the next write. The writer makes sure that 8 bytes are free before it copies. The idea is from
[orjson](https://github.com/ijl/orjson)'s `QUOTE_TAB`, which orjson took from
[sonic-rs](https://github.com/cloudwego/sonic-rs). Although dumping 100,000 log lines full of `\n`, `\t`, and quotes got
23% faster on an M1 Max, most of that came from writing straight into the write buffer instead of an intermediate one.
The table alone gained 2–7%.

## <span class="nj-theme">3</span> Own the number conversions { #theme-3 }

3.12.0 converted every floating-point number with `strtod` and every integer with `strtoull` or `strtoll`, after copying
the token into a buffer. `strtod` is correct, but general: it consults the locale for the decimal point, sets `errno`,
and handles any length of input. `std::from_chars` would avoid the locale, but it doesn't exist before C++17, and libc++
has its floating-point overloads without defining `__cpp_lib_to_chars`, so macOS builds could not detect it.

`canada.json`, a GeoJSON file of 111,126 numbers, shows what that costs. 108,528 of its numbers have 16 or 17
significant digits, like `-65.613616999999977`. The classic shortcut is Clinger's fast path ([Clinger,
1990](https://doi.org/10.1145/93542.93557)): write the number as its digits `w` times a power of ten, convert `w` to a
`double`, and multiply or divide it by that power of ten. If both are exact as `double`, that is, `w` is at most 2⁵³
(9,007,199,254,740,992) and the power at most 10²², the operation rounds only once, and the result is the correctly
rounded `double`. For most of `canada.json`'s numbers, `w` doesn't fit into 53 bits.

3.13.0 converts `float` and `double` numbers itself, without the C library and without the locale:

```mermaid
flowchart TB
    t["number token"] --> d{{"at most 19<br>significant digits?"}}
    d -->|"yes"| c{{"digits and power of ten<br>exact as double?"}}
    c -->|"yes"| cl["Clinger's fast path:<br>one multiplication or division"]
    c -->|"no"| el["Eisel-Lemire:<br>128-bit integer arithmetic"]
    d -->|"no"| el2["Eisel-Lemire on the first 19 digits"]
    el2 --> amb{{"w and w+1 round<br>to the same double?"}}
    amb -->|"yes"| done(["done"])
    amb -->|"no"| big["compare with the exact midpoint<br>(big-integer arithmetic)"]
```

<p class="nj-caption" markdown>How 3.13.0 converts a decimal token to a `double`. Of `canada.json`'s 111,080
floating-point numbers, 9,742 take Clinger's fast path and 101,338 Eisel-Lemire; none has more than 19 digits.</p>

### Eight digits at a time

On contiguous input and stream windows, the lexer accumulates the value while it validates the token, so the digits are
read once. The core is [fast_float](https://github.com/fastfloat/fast_float)'s eight-digit conversion: three
multiplications instead of eight.

```cpp
// v: eight ASCII digits, the first digit in the lowest byte
std::uint32_t parse_eight_digits(std::uint64_t v) noexcept
{
    v = ((v & 0x0F0F0F0F0F0F0F0Fu) * 2561u) >> 8u;            // 2561 = 10 * 2^8 + 1
    v = ((v & 0x00FF00FF00FF00FFu) * 6553601u) >> 16u;        // 6553601 = 100 * 2^16 + 1
    v = ((v & 0x0000FFFF0000FFFFu) * 42949672960001u) >> 32u; // 10000 * 2^32 + 1
    return static_cast<std::uint32_t>(v);
}
```

<p class="nj-code-caption" markdown>fast_float's conversion of eight ASCII digits to their value, with three
multiplications.</p>

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--swar" viewBox="0 0 600 430" role="img" aria-labelledby="nj-blog-digits nj-blog-digits-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-digits">Converting eight A&#8203;SCII digits to their value with three multiplications</title>
<desc id="nj-blog-digits-d">The text 12345678 as one word. Masking gives the digit values 1 to 8, one per byte. Multiplying by 10 times 2 to the 8 plus 1 and shifting gives 12, 34, 56 and 78 in 16-bit lanes; multiplying by 100 times 2 to the 16 plus 1 gives 1234 and 5678 in 32-bit lanes; multiplying by 10000 times 2 to the 32 plus 1 gives 12345678.</desc>
<text class="fg-h" x="40" y="20">eight A&#8203;SCII digits in one 64-bit word (byte 0 is the lowest)</text>
<rect class="fg-cell" x="40" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="69" y="53" text-anchor="middle">1</text>
<text class="nj-charts-tick" x="69" y="80">0x31</text>
<rect class="fg-cell" x="104" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="133" y="53" text-anchor="middle">2</text>
<text class="nj-charts-tick" x="133" y="80">0x32</text>
<rect class="fg-cell" x="168" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="197" y="53" text-anchor="middle">3</text>
<text class="nj-charts-tick" x="197" y="80">0x33</text>
<rect class="fg-cell" x="232" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="261" y="53" text-anchor="middle">4</text>
<text class="nj-charts-tick" x="261" y="80">0x34</text>
<rect class="fg-cell" x="296" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="325" y="53" text-anchor="middle">5</text>
<text class="nj-charts-tick" x="325" y="80">0x35</text>
<rect class="fg-cell" x="360" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="389" y="53" text-anchor="middle">6</text>
<text class="nj-charts-tick" x="389" y="80">0x36</text>
<rect class="fg-cell" x="424" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="453" y="53" text-anchor="middle">7</text>
<text class="nj-charts-tick" x="453" y="80">0x37</text>
<rect class="fg-cell" x="488" y="30" width="58" height="34" rx="4"/>
<text class="fg-code" x="517" y="53" text-anchor="middle">8</text>
<text class="nj-charts-tick" x="517" y="80">0x38</text>
<text class="fg-h" x="40" y="112">&amp; 0x0F0F0F0F0F0F0F0F: one digit value per byte</text>
<rect class="fg-cell" x="40" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="69" y="145" text-anchor="middle">1</text>
<rect class="fg-cell" x="104" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="133" y="145" text-anchor="middle">2</text>
<rect class="fg-cell" x="168" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="197" y="145" text-anchor="middle">3</text>
<rect class="fg-cell" x="232" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="261" y="145" text-anchor="middle">4</text>
<rect class="fg-cell" x="296" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="325" y="145" text-anchor="middle">5</text>
<rect class="fg-cell" x="360" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="389" y="145" text-anchor="middle">6</text>
<rect class="fg-cell" x="424" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="453" y="145" text-anchor="middle">7</text>
<rect class="fg-cell" x="488" y="122" width="58" height="34" rx="4"/>
<text class="fg-code" x="517" y="145" text-anchor="middle">8</text>
<text class="fg-h" x="40" y="186">× (10 · 2⁸ + 1) &gt;&gt; 8, every second byte kept: two digits per 16 bits</text>
<rect class="fg-cell" x="40" y="196" width="122" height="34" rx="4"/>
<text class="fg-code" x="101" y="219" text-anchor="middle">12</text>
<rect class="fg-cell" x="168" y="196" width="122" height="34" rx="4"/>
<text class="fg-code" x="229" y="219" text-anchor="middle">34</text>
<rect class="fg-cell" x="296" y="196" width="122" height="34" rx="4"/>
<text class="fg-code" x="357" y="219" text-anchor="middle">56</text>
<rect class="fg-cell" x="424" y="196" width="122" height="34" rx="4"/>
<text class="fg-code" x="485" y="219" text-anchor="middle">78</text>
<text class="fg-h" x="40" y="260">× (100 · 2¹⁶ + 1) &gt;&gt; 16, every second lane kept: four digits per 32 bits</text>
<rect class="fg-cell" x="40" y="270" width="250" height="34" rx="4"/>
<text class="fg-code" x="165" y="293" text-anchor="middle">1234</text>
<rect class="fg-cell" x="296" y="270" width="250" height="34" rx="4"/>
<text class="fg-code" x="421" y="293" text-anchor="middle">5678</text>
<text class="fg-h" x="40" y="334">× (10000 · 2³² + 1) &gt;&gt; 32: the value</text>
<rect class="fg-cell" x="40" y="344" width="506" height="34" rx="4"/>
<rect class="nj-charts-c1" fill-opacity=".25" x="40" y="344" width="506" height="34" rx="4"/>
<text class="fg-code" x="293" y="367" text-anchor="middle">12345678</text>
<text class="fg-note fg-note--l" x="40" y="400">Each step combines neighboring lanes, in all lanes of the word at once:</text>
<text class="fg-note fg-note--l" x="40" y="418">three multiplications instead of eight, and no branch.</text>
</svg>

</div>

<p class="nj-caption" markdown>`parse_eight_digits()` on `"12345678"`: multiplying by `10·2⁸ + 1` adds ten times each
byte to the byte above it, and the shift and the next mask keep every second lane.</p>

Checking that all eight bytes are digits takes one more expression. A digit is a byte from 0x30 to 0x39. In hexadecimal,
its upper half is 3 and its lower half is at most 9. Adding 6 tests the lower half: 0x39 + 6 = 0x3F still has the upper
half 3, but 0x3A + 6 = 0x40 carries into it. So a byte is a digit exactly if its upper half is 3 both before and after
adding 6, and with masks, that is one comparison for all eight bytes. An integer of up to 18 digits always fits into an
`int64_t`, and 19 digits into a `uint64_t`, so they need no overflow check.

### Clinger's fast path

Clinger's fast path is guarded by more than the two conditions above:

```cpp
#if !defined(FLT_EVAL_METHOD) || FLT_EVAL_METHOD == 0
if (exponent >= -22 && exponent <= 22 && w <= (std::uint64_t{1} << 53))
{
    double value = static_cast<double>(w);
    value = exponent < 0 ? value / exact_power_of_ten(-exponent)
                         : value * exact_power_of_ten(exponent);
    return negative ? -value : value;
}
#endif
```

<p class="nj-code-caption" markdown>Clinger's fast path: one correctly rounded multiplication or division, only without
x87 extended precision.</p>

With x87 arithmetic (`FLT_EVAL_METHOD != 0`), the intermediate result has extended precision and is rounded twice, so
those targets skip the fast path and take the integer-only route below.

### Eisel-Lemire

[Eisel-Lemire](https://arxiv.org/abs/2101.11408), adapted from fast_float's `compute_float`, handles everything else
with integers only: it multiplies the digits with a 128-bit approximation of `5^q` from a table and takes the mantissa
from the top of the product. For up to 19 digits, that always suffices ([Mushtak and Lemire,
2023](https://arxiv.org/abs/2212.06644)). Longer numbers, rare in JSON, are bracketed by their first 19 digits and that
plus one; only if the two round differently are all digits compared with the exact midpoint. [Appendix
I](#i-details-of-the-themes) has the details. Because it is integer arithmetic, the result no longer depends on the C
locale. (JSON always uses `.`, but `strtod` expects the locale's decimal separator, so 3.12.0 replaced the `.` before
calling it, which [failed for separators longer than one byte][5660].) [Appendix J](#j-validation) describes how the
conversion was checked against `strtod`.

### Writing: Żmij

For output, 3.12.0 used [Grisu2](https://doi.org/10.1145/1806596.1806623), which is fast but sometimes writes a 17th
digit where 16 suffice. 3.13.0 ports [Żmij](https://github.com/vitaut/zmij) by Victor Zverovich to C++11. It writes the
shortest decimal that reads back as the same `double`, and the closest one if there are several. Its digit conversion,
by Xiang JunBo, is the parser's divide-by-multiplying idea run backwards on all lanes of a word at once ([Appendix
I](#i-details-of-the-themes) shows it), and with SSE2 or NEON, Żmij's vector code (the NEON version by Dougall Johnson,
the SSE version by Tobias Schlüter) converts all 16 digits in one vector register.

One stall turned up on the way. To make room for the decimal point, the code first wrote all 16 digits, as two 8-byte
stores, and then moved the digits after the point one byte to the right: it loaded them and stored them one byte
further. That load came right after the two stores and read part of each. A CPU can hand a load the data of one store
that hasn't reached the cache yet, but it can't combine two, so the load had to wait until both stores were written. The
commit measured that wait as about 25% of the time to write a `double`. The vector version avoids memory: it keeps the
digits in a register, moves the ones after the point up by one byte there, puts `'.'` into the gap, and stores all 16
bytes once.

In the pull request's measurement, `dump()` of `canada.json` got about 3× as fast, on an M1 Max as well as on an x86-64
server with GCC and Clang. The changed output is listed in [Appendix F](#f-behavior-changes): 0.14% of random `double`s
are written differently, all of them with the same or fewer digits, and all of them read back as the same value.

## <span class="nj-theme">4</span> Don't do unnecessary work { #theme-4 }

A lot of what the 3.12.0 parser did was correct, cheap per call, and read by nobody in the common case.

### The token buffer

The old `get()` of theme <a class="nj-theme" href="#theme-1" title="theme 1">1</a> pushed every character into
`token_string`, a buffer that only the "last read" part of an error message uses. For seekable input, the lexer now
remembers the offset where the token started and copies the text from the input if an error happens. This is the 35%
step of the timeline: in the indented `citm_catalog.json`, every space of the indentation went through the buffer. For
streams, the carry buffer of theme <a class="nj-theme" href="#theme-1" title="theme 1">1</a> does the same job; the
per-character copy had been about 20% of what was left of a stream parse.

[`accept()`](../../api/basic_json/accept.md) went one step further: it doesn't copy strings and keys at all. The lexer
and the parser take a template parameter that drops values, so `accept()` gets its own instantiation without the copies.
That made validating `twitter.json` 11–13% faster on x86-64, and 19 files of simdjson's examples 12% by geometric mean.

### Positions only on error

For input that can be seeked, the lexer no longer counts lines and columns. The byte offset is the distance from the
start, and lines and columns are recomputed only when an error message needs them:

```cpp
std::size_t count_consumed_lines(std::size_t last_index, std::size_t& line_start) const
{
    const auto to = std::next(begin, last_index);
    using reverse_it = std::reverse_iterator<IteratorType>;
    const auto last_newline = std::find(reverse_it(to), reverse_it(begin), '\n');
    line_start = std::distance(begin, last_newline.base());   // column: offset - line_start
    return std::count(begin, last_newline.base(), '\n');      // line: newlines before it
}
```

<p class="nj-code-caption" markdown>Line and column of an error, computed from the byte offset only when an error
message needs them.</p>

That is linear in the input, but only an error pays for it. It is what [serde_json's slice
reader](https://github.com/serde-rs/json/blob/master/src/read.rs) does (`position_of_index()` with `memrchr` and a
newline count). A pending `unget()` is a flag, and the offset subtracts one for it, so `unget()` does no position work
at all. Measuring the two parts of the old `get()` separately on an M1 showed that the newline branch cost more than the
counters: removing only the branch saved 16% of validating an indented `twitter.json`, removing only the increments 4%.
Parsing `citm_catalog.json` got 12% faster.

### The text of float tokens

The lexer copied every float token into a buffer so that a SAX handler's `number_float(val, s)` could see the original
text: an out-of-line `std::string::append` per float, about 10% of parsing `canada.json`. The handlers behind
[`parse()`](../../api/basic_json/parse.md) and [`accept()`](../../api/basic_json/accept.md) never look at it. The parser
now recognizes them by their exact type:

```cpp
template<typename SAX> struct sax_ignores_number_text : std::false_type {};
template<typename B, typename IA, bool Collect, typename L>
struct sax_ignores_number_text<json_sax_dom_parser<B, IA, Collect, L>> : std::true_type {};
template<typename B>
struct sax_ignores_number_text<json_sax_acceptor<B>> : std::true_type {};
// json_sax_dom_callback_parser likewise

// at the call site
sax->number_float(res, number_float_text(sax));   // an empty string for the handlers above
```

<p class="nj-code-caption" markdown>Recognizing the library's own SAX handlers, which never read the text of a float
token.</p>

A class derived from `json_sax_dom_parser` does not match the specialization, so it keeps getting the exact text. For
every other handler, the lexer only records a pointer to the token and its length, and copies on the first
`get_string()`. That is safe for contiguous input, which has to outlive the parse anyway; in a stream's window, the next
refill could overwrite the text, so there the copy is made at once. The first version put the "is there pending text?"
check into the `get_string()` that keys and strings use too, and lost 2–3% on string-heavy input. Keys and strings now
call a separate function without the check. Parsing `canada.json` got 9–11% faster.

### A copy that should have been a move

[`from_cbor()`](../../api/basic_json/from_cbor.md) and the other binary readers ended like this:

```cpp
return res ? result : basic_json(value_t::discarded);   // 3.12.0
```

<p class="nj-code-caption" markdown>The end of the 3.12.0 binary readers: the conditional operator copies `result`.</p>

`result` is a local, but the conditional operator's operand is an lvalue expression, and the implicit move on `return`
applies only to a returned name. So every successfully parsed value was deep-copied once and then destroyed. 3.13.0
assigns `discarded` to `result` on failure and returns `result` by name. Decoding a 2 MB CBOR document went from 26.99
ms to 14.65 ms. The copy was also a stack-overflow risk: the copy constructor recursed once per level, for a value the
reader had already accepted.

### `ordered_json` growth

[`ordered_json`](../../api/ordered_json.md) stores its members in a `std::vector<std::pair<const std::string, json>>`.
Because the key is `const`, the pair's "move" constructor copies the key and can throw. When `std::vector` grows, it
uses `std::move_if_noexcept` to keep the strong exception guarantee, so for this element type it copies every element,
including the whole subtree behind every value. The library now grows the storage itself, in two phases:

```cpp
// phase 1, may throw but only touches tmp:
// copy the keys, default-construct the values, add the new element
Container tmp(this->get_allocator());
tmp.reserve((std::max)(size_type{1}, 2 * this->size()));
for (const auto& element : *this)
    tmp.emplace_back(std::piecewise_construct, std::forward_as_tuple(element.first),
                     std::forward_as_tuple());
tmp.emplace_back(std::forward<Args>(args)...);
// phase 2, cannot throw: move-assign the values, adopt the storage
auto it = tmp.begin();
for (auto& element : *this) { it->second = std::move(element.second); ++it; }
Container::swap(tmp);
```

<p class="nj-code-caption" markdown>How `ordered_map` grows its storage in two phases, without copying the values.</p>

The new element is constructed before any value is moved, so `j.emplace("new", std::move(j["old"]))` still works, and
the strong guarantee holds without a `try`, which matters because the library also builds with `-fno-exceptions`.
Parsing `twitter.json` into `ordered_json` needs 33% of the allocations and, in the pull request's measurement, about
50% of the time. Unfortunately, compilers with the EDG front end (Intel's icpc, NVIDIA's nvc++) consider that pair's
move constructor `noexcept`. There, the vector already "moves", the new path is not taken, and a key copy that throws
during growth calls `std::terminate`.

### Containers built one element at a time

The DOM parser used to `push_back` every element into its array, and insert every member into its object as soon as it
was parsed. Now all open arrays share one stack of elements; when an array of up to 16 elements ends, it is constructed
at its exact size from a range of move iterators, one allocation. `ordered_json` objects collect up to 32 members the
same way, with a linear duplicate-key check over that short slice, and larger objects get a side table of hashes for
that check from 64 members on. An `ordered_json` object with very many members went from 43 million instructions to 1.9
million, and `ordered_json` now parses 1–15% *faster* than `json` in our suite, since `json`'s `std::map` still
allocates a node per member. The binary readers know their sizes up front and use a separate handler without the stack;
sharing it had made them 5–12% slower with GCC.

The binary readers also stopped taking every element through their general dispatch. When an array opens, the CBOR and
MessagePack readers read the numbers, booleans, and nulls that follow in one loop, and the UBJSON and BJData readers do
the same for arrays with a type marker. Reading an array of a million integers from CBOR or MessagePack got 42–47%
faster, and `canada.json` 10%. Arrays of one element skip the loop: in 1,000 arrays nested in each other, each entered
it only to find another array, which cost 6–8%. Now the loop costs nested arrays nothing measurable, and costs 100,000
arrays `[1,2]` at most 1.5%.

### Smaller ones

The parser checks for the expected `:` or `,` before it falls into the lexer's general token switch (−7% on
`citm_catalog.json`, a contribution by [@mvanslobbe](https://github.com/mvanslobbe)), and
[`to_cbor()`](../../api/basic_json/to_cbor.md) no longer creates a temporary `basic_json` for every object key it writes
(−55% on `twitter.json`, by [@alexprabhat99](https://github.com/alexprabhat99)). And the binary readers wrote every
byte of a string twice: they grew the string with `resize()`, which fills it with zeros, and then copied the bytes over
the zeros. The zero fill alone was 5% of the instructions of `from_cbor()`. A string that the input holds in one block
is now appended from it directly, after its claimed length has been checked against the input, so a huge claimed
length still allocates nothing. Reading `twitter.json` and `citm_catalog.json` from CBOR and MessagePack got 5–9%
faster on the M1, 3–9% on x86-64.

!!! note "The same idea, measured twice"

    The SAX interface hands the lexer's buffer to the handler as `string_t&` and allows it to be moved from; the lexer
    starts each token with an empty buffer anyway. In September, moving string values instead of copying them saved
    2–3%. We measured moving keys too, and dropped it. The buffer is sized for the longest token so far, and keys are
    short while values are long. So moving a key hands a large buffer to a short string, and the next value has to grow
    a new one: 11.9% slower on 40,000 short strings. In October, with much of the lexer around it rewritten, moving keys
    was measured again: `parse()` of `twitter.json` got 3.3% faster with Clang and 5.0% with GCC, so keys are moved now
    too. An idea that lost once is worth measuring again when the code around it changes.

## <span class="nj-theme">5</span> Read the assembly { #theme-5 }

A good part of 3.13.0 came from reading what the compiler made of the hot loops, with Clang's `-Rpass-missed=inline`,
profiles, and instruction counts. None of the following shows up in the source as a problem.

### A stack canary on every token

The function that dispatches on the first byte of a token built the expected text of `true`, `false`, and `null` in
local arrays:

```cpp
case 't':   // 3.12.0
{
    std::array<char_type, 4> true_literal = {{'t', 'r', 'u', 'e'}};
    return scan_literal(true_literal.data(), true_literal.size(), token_type::literal_true);
}
```

<p class="nj-code-caption" markdown>The 3.12.0 lexer's dispatch for `true`: a local array, and with it a stack canary.</p>

With `-fstack-protector-strong`, which Ubuntu's GCC enables by default and many distributions use for their packages,
*any* local array gives a function a stack canary: the prologue loads a secret (on x86-64 Linux from thread-local
storage) and stores it next to the locals, and every return compares it. Even worse, that happens on every call, also
for the `[`, `,` and `"` tokens that never touch the array. The canary's load alone was 11% of the function's samples.
(Plain `-fstack-protector` only protects character arrays of at least 8 bytes, so it didn't trigger here.) Now the
literal is a string literal whose length is a template parameter, compared on contiguous input with one `memcmp` of
constant size, and the dispatch has no canary and no array on the stack:

```cpp
case 't': return scan_literal("rue", token_type::literal_true);

template<std::size_t N>
JSON_HEDLEY_NEVER_INLINE token_type scan_literal(const char (&rest)[N], token_type return_type);
```

<p class="nj-code-caption" markdown>The 3.13.0 dispatch: a string literal whose length is a template parameter.</p>

`scan_literal()` is deliberately out of line: inlined, it made Clang's dispatch grow from 233 to 278 instructions, and
slower. Together with the next change, validating `canada.json` got 10.5% faster with GCC on x86-64. The same change
replaced the parser's `std::vector<bool>` nesting stack, whose `push_back` GCC called out of line, with
`std::vector<std::uint8_t>`; a bit vector saves memory that a stack of nesting levels doesn't need.

### Exceptions that block inlining

A function that can throw builds the message, allocates the exception, and needs a landing pad for every temporary, even
if the throw never happens:

```cpp
if (JSON_HEDLEY_LIKELY(ptr != nullptr)) { return *ptr; }   // 3.12.0, get_ref()
JSON_THROW(type_error::create(303, detail::concat(
    "incompatible ReferenceType for get_ref, actual type is ", obj.type_name()), &obj));
```

<p class="nj-code-caption" markdown>The throw in 3.12.0's `get_ref()`: building the message makes the function too big
to inline.</p>

That made [`get_ref()`](../../api/basic_json/get_ref.md), [`operator[]`](../../api/basic_json/operator%5B%5D.md),
[`at()`](../../api/basic_json/at.md) and the iterator operators too big to inline, and gave callers large frames (192
bytes for `get_ref()` with GCC). 3.13.0 moves construction and `throw` into helpers marked `[[noreturn]]` and never
inlined, so the hot function keeps a test and a call:

```cpp
if (JSON_HEDLEY_LIKELY(ptr != nullptr)) { return *ptr; }
throw_incompatible_reference_type(obj);   // JSON_HEDLEY_NO_RETURN JSON_HEDLEY_NEVER_INLINE
```

<p class="nj-code-caption" markdown>The same function in 3.13.0: a test and a call of a helper that is never inlined.</p>

That fixed 27 throw sites. Iterator arithmetic got 6× as fast with Clang, and `std::sort` over a `json` array of 10,000
integers in user code 6–9% faster.

The value's own lifecycle had the same problem: the destructor, the copy constructor, and
[`operator==`](../../api/basic_json/operator_eq.md) contained the code for every type, so they were too big to inline
even for a number. Clang reported about 380 call sites where they were not inlined. Now the destructor and the copy
constructor start with an inline test whether the value owns memory, which Clang compiles to one bit test
(`1 << type & 0x10E`), `operator==` with one for two scalars of the same type, and the rest is out of line. `j == 5`
went from 3.55 ns to 0.65 ns with Clang. It is not free: a test file of `extern "C"` wrappers around the library's
functions, which we compile to check what gets inlined, grew by 13% at `-O2`, and with GCC, `operator==` on large
documents got about 7% slower.

### Aliasing

C++ allows a `char` to access any object, so a store through a `char` pointer may change any object whose address the
compiler can't rule out. In a writer that keeps its write position `pos` in a member, `buffer[pos++] = c` therefore
costs more than it looks: the compiler can't prove that the store of `c` didn't overwrite `pos` itself, so it writes
`pos` to memory before every character and loads it again after. A local variable whose address never escapes can't be
reached by any store, and stays in a register:

```cpp
std::size_t pos = write_buffer_pos;   // a local: no char store can reach it
// ... write_buffer[pos++] = digit; ...
write_buffer_pos = pos;               // published once at the end
```

<p class="nj-code-caption" markdown>Keeping the write position in a local, so that the compiler can keep it in a
register.</p>

On a 4 MiB binary value, [`dump()`](../../api/basic_json/dump.md) went from 18.0 ms to 7.4 ms with this change alone.
`json_document`'s writer and the binary writers keep their cursors in locals for the same reason, and publish them
before any call that could see them.

### Loop shape beats branch count

A change that removed one branch per whitespace byte made scanning long runs of indentation 1.75–3.2× *slower* with
Clang and GCC. It had rewritten `do { get(); } while (is_whitespace());` into
`get(); while (is_whitespace()) { get_ignoring_pending_unget(); }`, and the assembly showed why it lost: neither
compiler kept the input's read and end pointers in registers any more, and both reloaded them from memory on every
character. Restoring the do-while shape, `get(); if (is_whitespace()) { do { ... } while (is_whitespace()); }`, fixed
it. We don't know why the while loop lost the registers, only that the do-while shape gets them back.

### Inlining that disappears

Inlining is a budget per function. Once the string writer had grown, GCC 13 and 16 stopped inlining two tiny, unchanged
helpers into the pretty-printing loop, and indented output got up to 13% slower. They are now forced inline. A change in
one place silently made an unrelated loop slower; only a benchmark of indented output noticed.

### Branches the compiler chose

[`json_document`](../../api/json_document.md) writes most floats of `canada.json` by deciding, from where the `double`
lies relative to its source text, which of two or three candidate digit strings to write. The conditions of those
selections depend on the digits, so they are as good as random:

```cpp
const bool up = from > 37 * one;
const bool shorter = biased_distance(from - (up ? 10 * one : 0)) < radius;
const std::uint64_t a = w - r10 + (up ? 10u : 0u);
return shorter ? a : b;
```

<p class="nj-code-caption" markdown>Selecting a candidate digit string: GCC 13 compiled the conditional operators as
jumps.</p>

Clang compiled the `?:` as conditional moves; GCC 13 compiled them as jumps. With nothing to tell it that the conditions
are unpredictable, a branch that skips some work looks cheaper than computing both sides.
[Callgrind](https://valgrind.org/docs/manual/cl-manual.html)'s branch simulation counted 220,000 mispredictions per dump
of `canada.json` with GCC, against 97,000 with Clang. Written as masks, which have no branch form to reconstruct, the
selections stay branch-free with GCC and Clang:

```cpp
// all ones or zero
std::uint64_t mask_if(bool b) { return std::uint64_t{0} - static_cast<std::uint64_t>(b); }
std::uint64_t select_if(bool b, std::uint64_t a, std::uint64_t c)
{
    return c ^ ((a ^ c) & mask_if(b));
}

const bool shorter = biased_distance(from - (mask_if(up) & (10 * one))) < radius;
const std::uint64_t a = w - r10 + (mask_if(up) & 10u);
return select_if(shorter, a, b);
```

<p class="nj-code-caption" markdown>The same selections written as masks, which stay branch-free with GCC and Clang.</p>

With GCC on x86-64, the mispredictions went down to 98,000, and the dump of `canada.json` got about 15% faster with 5%
*more* instructions. With Clang, the time stayed the same. We found this one while writing this post.

### Code size as a cost

[`get<std::array<int, 1000>>()`](../../api/basic_json/get.md) used a pack expansion, `{{ j.at(Idx).get<T>()... }}`. A
pack expansion is unrolled before the optimizer decides anything, so once `at()` had become small enough to inline,
Clang emitted one function of about 28,000 instructions (with 3.12.0, about 8,000): a thousand inlined copies of the
bounds and type checks. Its time moved from 657 to 957 ns just by aligning the code differently. A loop needs 49
instructions.

!!! note "Instruction counts, not only time"

    On the x86-64 machine we used for checking, moving code by a few bytes changed the time of unrelated benchmarks by
    up to ±5%. Many decisions were therefore made on instruction counts (callgrind on Linux, `/usr/bin/time -l` on
    macOS), checked against timings of builds with all functions and loops aligned to 64 bytes, and timed interleaved in
    one binary with several code layouts. The target, applied strictly in the later changes, was: at least 3% faster,
    and no benchmark more than 1% slower. Some changes accepted a small loss elsewhere and say so, such as the 7% on
    GCC's `operator==` above. The branch example shows the limit of that rule: it is faster with more instructions.

## <span class="nj-theme">6</span> Write through a cursor { #theme-6 }

In 3.12.0, every [`dump()`](../../api/basic_json/dump.md) created its output adapter with `std::make_shared`, built a
512-character indentation string, and the serializer wrote every structural character through a virtual call:

```cpp
o->write_characters("{\n", 2);
o->write_characters(indent_string.c_str(), new_indent);
o->write_character('\"');
```

<p class="nj-code-caption" markdown>How the 3.12.0 serializer wrote an object's opening brace and the start of a key:
three virtual calls.</p>

The writing side changed in five steps, one per subsection below:

```mermaid
flowchart LR
    subgraph before["3.12.0"]
        direction LR
        d1["dump()"] --> a1["make_shared<br>output adapter"] --> v1["virtual call<br>per write"] --> s1[("std::string")]
    end
    subgraph after["3.13.0"]
        direction LR
        d2["dump()"] --> a2["adapter on<br>the stack"] --> b2["1 KiB buffer,<br>bulk append"] --> s2[("std::string")]
    end
```

<p class="nj-caption" markdown>The text serializer's output path before and after the first two steps.</p>

### A buffer in the serializer

All writes go into a 1 KiB buffer that is flushed in bulk, so the virtual call happens once per KiB, and neighboring
writes can be merged. Runs longer than the buffer are written straight through, so they are not copied twice.

```cpp
void put_char(char c)
{
    if (JSON_HEDLEY_UNLIKELY(write_buffer_pos == write_buffer.size())) { flush(); }   // virtual
    write_buffer[write_buffer_pos++] = c;
}
```

<p class="nj-code-caption" markdown>Writing one character: the virtual call happens only when the buffer is full.</p>

### No allocation per call

The adapter lives on the stack, and there is no indentation string any more: `dump(4)` writes the spaces straight into
the buffer. A compact `dump()` of a small object went from 4 heap allocations to 1 with libstdc++ (3 to 1 with libc++):
the returned string, and none if it fits into the string's small buffer.

### A concrete sink for the binary writers

The overloads of [`to_cbor()`](../../api/basic_json/to_cbor.md) and friends that return a `std::vector` use a writer
that is a template over the sink type, with no virtual call. Byte order is now swapped with `__builtin_bswap*` (or
`_byteswap_*` with MSVC) instead of `std::reverse` on a byte array: compilers can recognize the reversal as a byte swap
in a small function, but in the CBOR number path, Clang emitted no `bswap` at all. Writing into a vector also allows
[`to_bson()`](../../api/basic_json/to_bson.md) to make one pass instead of two, because a vector can be written to at
any position: BSON puts the size of every document in front of it, so the writer used to walk the value once for the
sizes and once to write. It now writes a placeholder and fills in the size when the document is complete, 12–20% faster
on the M1. Streams and other output adapters, which can only append, still take two passes.

### A cursor instead of `vector::insert()`

After the previous step, writing an array of integers as CBOR was still no faster than in 3.12.0, and slower with GCC.
The profile said why: each number's one to eight bytes were appended with `vector::insert()`, which both standard
libraries implement as an out-of-line insert-anywhere routine; it took 30% of the time, more than encoding the numbers.
The sink now keeps a cursor and a limit pointer, reserves space for a whole run of numbers at once, and writes through
the cursor:

```cpp
CharType* const start = oa.reserve(max_run * integer_encoding_space);   // one check per run
CharType* out = start;
for (n = 0; n < max_run && it != end && it->is_number_integer(); ++n, ++it)
{
    out += encode_integer(out, *it);
}
oa.commit(out - start);
```

<p class="nj-code-caption" markdown>Encoding a run of integers through a cursor, with one capacity check for the whole
run.</p>

The cursor needs the vector to be as long as the space it writes into, so the sink grew it with `resize()` to its whole
new capacity. That zeroes the new bytes, so every doubling zeroed megabytes of fresh memory at once: it faulted in all
the pages and pushed them out of the cache before the writer got there. The writers had gained much less on x86-64 than
on the M1 (writing an array of numbers as CBOR got 2.4× as fast on a Skylake laptop and 4.8× on the M1 Max), and this
was part of the reason: page faults, zeroing and copies on reallocation of a 9–80 MB output were 30–76% of the 3.13.0
time on x86-64. The sink still reserves the same capacity, but now resizes the vector only to 64 KiB ahead of the
cursor, a window that is still in the cache when the writer's stores arrive. On x86-64, writing large arrays of numbers
got 9–26% faster; on the M1, 1–2.5%.

### Integers without branches

The last step also took the branches out of encoding an integer. After the bounds checks, mispredicted branches
accounted for about 40% of the remaining time: the type, the sign, and the 1-, 2-, 4-, or 8-byte size class of each
integer in a stream are hard to predict. The encoder reads signed and unsigned integers through one masked path, looks
the size class up from the number of leading zero bits, and stores the head as one byte plus one 8-byte word, of which
the caller keeps only as many bytes as the class needs:

```cpp
// 1, 2, 3 or 4 if x fits 1, 2, 4 or 8 bytes, without a branch
static unsigned integer_size_class(const std::uint64_t x) noexcept
{
    static constexpr std::array<std::uint8_t, 64> size_class_by_leading_zeros = { /* ... */ };
    return size_class_by_leading_zeros[count_leading_zeros(x | 1u)];
}

std::size_t encode_first_byte_and_tail(CharType* out, std::uint8_t first_byte,
                                       unsigned size_class, std::uint64_t value) const noexcept
{
    out[0] = to_char_type(first_byte);
    const unsigned unused_bits = 64u - ((8u << size_class) >> 1u);
    const std::uint64_t tail = is_little_endian ? byteswap(value) >> unused_bits
                                                : value << unused_bits;
    // always 8 bytes; the caller keeps the first 0, 1, 2, 4 or 8
    std::memcpy(out + 1, &tail, sizeof(tail));
    return ((std::size_t{1} << size_class) >> 1u) + 1;
}
```

<p class="nj-code-caption" markdown>Encoding the head of a CBOR integer without a branch: the size class from a table,
the tail as one 8-byte store.</p>

The table is a table because Clang vectorized the equivalent comparisons into slower code, and the unconditional 8-byte
store is why `reserve()` asks for 9 bytes per integer. Writing an array of small signed integers as CBOR, which had not
gotten faster before, is now 4.2× as fast as with 3.12.0 with Clang on an M1 Max, and was 2.8× as fast with GCC 13 on
x86-64 when the change was made. One more lesson from these changes: the loop over an array is a separate function that
is never inlined. Inlined into the function that writes any value, its register needs made every call of that function
save more registers, once per nested value, which cost `citm_catalog.json` 13%.

## <span class="nj-theme">7</span> Fix the algorithm first { #theme-7 }

None of the micro-optimizations above matter much next to an algorithm that is quadratic. Seven operations were
quadratic or worse in 3.12.0. They are fixes of cases most programs never hit, not tuning, so they are not part of the
3.0× above (except `flatten()`, which the suite happens to measure); [Appendix D](#d-algorithmic-fixes) has the numbers:

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog" viewBox="0 0 600 380" role="img" aria-labelledby="nj-blog-cliffs nj-blog-cliffs-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-cliffs">Operations that grew quadratically or worse: time with 3.12.0 and 3.13.0, log scale</title>
<desc id="nj-blog-cliffs-d">Dot plot on a logarithmic time axis, less is better; an arrow leads from each 3.12.0 time to the 3.13.0 time. diff() 64k numbers vs []: 4237 ms to 10.8 ms; diff() 20k objects vs half: 122 ms to 4.13 ms; parse() callback, 32k objects: 1398 ms to 12.1 ms; operator&lt; nested 24 deep: 64.4 ms to 0.002 ms; operator&lt; citm, 10x: 284 ms to 3.94 ms; flatten() citm, ordered_json: 271 ms to 1.45 ms; to_bson() 200 deep, 100x: 20.3 ms to 0.352 ms; push_back() 100k, diagnostics: 1589 ms to 5.32 ms; at(i) 10k, diagnostics: 45.9 ms to 0.088 ms.</desc>
<line class="nj-charts-grid" x1="250" y1="30" x2="250" y2="336"/>
<text class="nj-charts-tick" x="250" y="352">1 µs</text>
<line class="nj-charts-grid" x1="297.857" y1="30" x2="297.857" y2="336"/>
<text class="nj-charts-tick" x="297.857" y="352">10 µs</text>
<line class="nj-charts-grid" x1="345.714" y1="30" x2="345.714" y2="336"/>
<text class="nj-charts-tick" x="345.714" y="352">0.1 ms</text>
<line class="nj-charts-grid" x1="393.571" y1="30" x2="393.571" y2="336"/>
<text class="nj-charts-tick" x="393.571" y="352">1 ms</text>
<line class="nj-charts-grid" x1="441.429" y1="30" x2="441.429" y2="336"/>
<text class="nj-charts-tick" x="441.429" y="352">10 ms</text>
<line class="nj-charts-grid" x1="489.286" y1="30" x2="489.286" y2="336"/>
<text class="nj-charts-tick" x="489.286" y="352">0.1 s</text>
<line class="nj-charts-grid" x1="537.143" y1="30" x2="537.143" y2="336"/>
<text class="nj-charts-tick" x="537.143" y="352">1 s</text>
<line class="nj-charts-grid" x1="585" y1="30" x2="585" y2="336"/>
<text class="nj-charts-tick" x="585" y="352">10 s</text>
<text class="nj-charts-tick" x="417.5" y="370">runtime (log scale), less is better</text>
<defs><marker id="nj-blog-cliffs-head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path class="nj-charts-head" d="M0 0 L10 5 L0 10 z"/></marker></defs>
<circle class="nj-charts-ojson-dot" cx="250" cy="14" r="5"/><text class="nj-charts-leg" x="260" y="18.5">3.12.0</text>
<circle class="nj-charts-json-dot" cx="330" cy="14" r="5"/><text class="nj-charts-leg" x="340" y="18.5">3.13.0</text>
<text class="nj-charts-rowlabel" x="240" y="52" text-anchor="end">diff() 64k numbers vs []</text>
<line class="nj-charts-axis" x1="561.152" y1="48" x2="450.028" y2="48" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="567.152" cy="48" r="5"><title>diff() 64k numbers vs [], 3.12.0: 4237 ms</title></circle>
<circle class="nj-charts-json-dot" cx="443.028" cy="48" r="5"><title>diff() 64k numbers vs [], 3.13.0: 10.8 ms</title></circle>
<text class="nj-charts-factor" x="505.09" y="41">392&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="86" text-anchor="end">diff() 20k objects vs half</text>
<line class="nj-charts-axis" x1="487.419" y1="82" x2="430.049" y2="82" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="493.419" cy="82" r="5"><title>diff() 20k objects vs half, 3.12.0: 122 ms</title></circle>
<circle class="nj-charts-json-dot" cx="423.049" cy="82" r="5"><title>diff() 20k objects vs half, 3.13.0: 4.13 ms</title></circle>
<text class="nj-charts-factor" x="458.234" y="75">30&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="120" text-anchor="end">parse() callback, 32k objects</text>
<line class="nj-charts-axis" x1="538.106" y1="116" x2="452.39" y2="116" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="544.106" cy="116" r="5"><title>parse() callback, 32k objects, 3.12.0: 1398 ms</title></circle>
<circle class="nj-charts-json-dot" cx="445.39" cy="116" r="5"><title>parse() callback, 32k objects, 3.13.0: 12.1 ms</title></circle>
<text class="nj-charts-factor" x="494.748" y="109">116&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="154" text-anchor="end">operator&lt; nested 24 deep</text>
<line class="nj-charts-axis" x1="474.14" y1="150" x2="271.406" y2="150" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="480.14" cy="150" r="5"><title>operator&lt; nested 24 deep, 3.12.0: 64.4 ms</title></circle>
<circle class="nj-charts-json-dot" cx="264.406" cy="150" r="5"><title>operator&lt; nested 24 deep, 3.13.0: 0.002 ms</title></circle>
<text class="nj-charts-factor" x="372.273" y="143">32200&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="188" text-anchor="end">operator&lt; citm, 10x</text>
<line class="nj-charts-axis" x1="504.98" y1="184" x2="429.07" y2="184" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="510.98" cy="184" r="5"><title>operator&lt; citm, 10x, 3.12.0: 284 ms</title></circle>
<circle class="nj-charts-json-dot" cx="422.07" cy="184" r="5"><title>operator&lt; citm, 10x, 3.13.0: 3.94 ms</title></circle>
<text class="nj-charts-factor" x="466.525" y="177">72&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="222" text-anchor="end">flatten() citm, ordered_json</text>
<line class="nj-charts-axis" x1="504.006" y1="218" x2="408.294" y2="218" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="510.006" cy="218" r="5"><title>flatten() citm, ordered_json, 3.12.0: 271 ms</title></circle>
<circle class="nj-charts-json-dot" cx="401.294" cy="218" r="5"><title>flatten() citm, ordered_json, 3.13.0: 1.45 ms</title></circle>
<text class="nj-charts-factor" x="455.65" y="211">187&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="256" text-anchor="end">to_bson() 200 deep, 100x</text>
<line class="nj-charts-axis" x1="450.144" y1="252" x2="378.87" y2="252" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="456.144" cy="252" r="5"><title>to_bson() 200 deep, 100x, 3.12.0: 20.3 ms</title></circle>
<circle class="nj-charts-json-dot" cx="371.87" cy="252" r="5"><title>to_bson() 200 deep, 100x, 3.13.0: 0.352 ms</title></circle>
<text class="nj-charts-factor" x="414.007" y="245">58&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="290" text-anchor="end">push_back() 100k, diagnostics</text>
<line class="nj-charts-axis" x1="540.768" y1="286" x2="435.311" y2="286" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="546.768" cy="286" r="5"><title>push_back() 100k, diagnostics, 3.12.0: 1589 ms</title></circle>
<circle class="nj-charts-json-dot" cx="428.311" cy="286" r="5"><title>push_back() 100k, diagnostics, 3.13.0: 5.32 ms</title></circle>
<text class="nj-charts-factor" x="487.54" y="279">299&#215;</text>
<text class="nj-charts-rowlabel" x="240" y="324" text-anchor="end">at(i) 10k, diagnostics</text>
<line class="nj-charts-axis" x1="467.101" y1="320" x2="350.057" y2="320" marker-end="url(#nj-blog-cliffs-head)"/>
<circle class="nj-charts-ojson-dot" cx="473.101" cy="320" r="5"><title>at(i) 10k, diagnostics, 3.12.0: 45.9 ms</title></circle>
<circle class="nj-charts-json-dot" cx="343.057" cy="320" r="5"><title>at(i) 10k, diagnostics, 3.13.0: 0.088 ms</title></circle>
<text class="nj-charts-factor" x="408.079" y="313">522&#215;</text>
</svg>

</div>

<p class="nj-caption" markdown>Operations that were quadratic or worse in 3.12.0, on a logarithmic scale; each arrow
leads from the time with 3.12.0 to the time with 3.13.0. Less is better.</p>

### Comparing in one pass

The most instructive one is [`operator<`](../../api/basic_json/operator_lt.md). Before C++20, `json`'s `operator<` on
two arrays or objects called the `operator<` of `std::vector` or `std::map`, which is `std::lexicographical_compare`.
For every pair of elements it asks `a < b` and, if that is false, `b < a`. When the elements are themselves containers,
both questions recurse into the whole subtree, and when they are equal, both have to go all the way down. So each level
of nesting doubles the work: two equal values nested 20 levels deep took 5.7 ms, 30 levels 3.8 seconds, and 40 levels
would take about an hour. That matters to anyone who keeps `json` values in a `std::set`, uses them as `std::map` keys,
or sorts them. Since C++20, `operator<` is derived from [`operator<=>`](../../api/basic_json/operator_spaceship.md),
which asks once and was never affected.

3.13.0 compares in one pass over an explicit stack of iterator pairs and gets "less", "equal", "greater" or "unordered"
for each pair at once, so the ordering question is asked once per element. We found two subtleties by comparing 68,121
results with the old code, not by reading it. `std::lexicographical_compare` steps over a pair it cannot order (a NaN)
and goes on, while the three-way version stops there, so the pass has a flag for which behavior the caller needs. And
object keys must be compared with `operator==` when testing equality, not with the object's comparator: for
`ordered_json`, that comparator is `std::equal_to`, and using it as "less" reports every equal key as smaller. The
single pass has a price: ordering flat arrays of numbers got 27% slower, while flat objects got 34% faster, in the pull
request's measurement.

### Bounded recursion

The other side of this theme is depth. A value nested 100,000 levels deep used to crash `dump()`, the copy constructor,
`std::hash`, [`flatten()`](../../api/basic_json/flatten.md) and the BSON and UBJSON writers with a stack overflow, and
in optimized builds `operator==`, [`diff()`](../../api/basic_json/diff.md) and the other binary writers at 300,000
levels; servers that copy JSON from clients hit that. Other libraries limit the depth of what they parse
([Boost.JSON](https://github.com/boostorg/json) at 32, [serde_json](https://github.com/serde-rs/json) at 128,
[simdjson](https://github.com/simdjson/simdjson) at 1024) or parse and write iteratively
([yyjson](https://github.com/ibireme/yyjson)), and [RapidJSON](https://github.com/Tencent/rapidjson) parses recursively
unless asked otherwise. We tried making every walk iterative, but that made `dump()`, copying and merging up to 20%
slower on ordinary documents. So 3.13.0 bounds the recursion instead:

```cpp
constexpr std::size_t recursion_depth_limit() noexcept { return 128; }

static void destroy_bounded(basic_json& v, std::size_t depth) noexcept
{
    if (JSON_HEDLEY_UNLIKELY(depth >= detail::recursion_depth_limit()))
    {
        destroy_walk(v);   // deeper than 128 levels: no recursion at all (below)
        return;
    }
    // for each child that is a container: destroy_bounded(child, depth + 1)
    free_container(v);
}
```

<p class="nj-code-caption" markdown>Bounded recursion: recursive down to 128 levels, iterative below.</p>

The first 128 levels run the old recursive code, and only below that does an explicit stack, or the walk below, take
over. A document nested less deeply pays one comparison per container. Testing for equality walks `std::vector` and
`std::map` itself and passes the depth as an argument. Copying can't do that cheaply: the containers' copy constructors
call ours for every element, and a copy that inserts element by element so that it can pass the depth measured 4–16%
slower, because `std::map`'s own copy clones its tree without comparing a single key. So copying counts the levels in a
`thread_local` counter instead, about ten nanoseconds per copy of a small object. Three more operations use the same
counter: converting a value from another `basic_json` specialization, the ordering comparisons (`<`, `<=>` and the
operators derived from them), and equality for custom container types, whose own `operator==` calls ours.

### Destroying without a stack

The destructor's walk for deep values uses pointer reversal, the idea behind the [Schorr-Waite graph marking
algorithm](https://doi.org/10.1145/363534.363554): while it empties a container, the slot of that container's last child
holds the link back to the container's parent, so the way back needs no memory ([Appendix I](#i-details-of-the-themes)
shows the loop). The walk allocates nothing and calls nothing that can throw, which fixed two older bugs: the previous
destructor flattened children into a `std::vector`, which ignored the allocator type and could let `std::bad_alloc`
escape from a `noexcept` destructor. A test checks with a counting allocator that destroying any value allocates
nothing. Against 3.12.0, destroying a parsed document is 1.24–1.55× as fast in our suite, and destroying an array of one
million small objects 1.39×.

## <span class="nj-theme">8</span> Build a different data structure { #theme-8 }

After all of the above, [`json::parse()`](../../api/basic_json/parse.md) is still bound by what it builds: one heap
allocation per string, array and object, and a `std::map` node per member, all of which have to be freed again. Many
programs only parse a document, read some fields and throw it away, or change a few values and write it back. For them,
3.13.0 adds [`json_document`](../../features/json_view/index.md) and `json_view` in a new header, `<nlohmann/json_view.hpp>`.
The two figures below show what each parser makes of this 54-byte text:

```json
{"port": 6379, "price": 19.90, "tags": ["eu", "a\"b"]}
```

<p class="nj-code-caption" markdown>The example text of the next two figures.</p>

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-jsonview " viewBox="0 0 840 222" role="img" aria-labelledby="fig-jvlt-title fig-jvlt-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jvlt-title">A J&#8203;SON text parsed by basic_json::parse()</title>
<desc id="fig-jvlt-title-d">The text {&quot;port&quot;: 6379, &quot;price&quot;: 19.90, &quot;tags&quot;: [&quot;eu&quot;, &quot;a\&quot;b&quot;]} parsed by basic_json::parse(): the root json value points to a std::map whose three nodes are separate heap allocations; the price is stored as the double 19.9; the tags array is a std::vector of two json values, each pointing to its own std::string.</desc>
<defs>
<marker id="jvlt-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-str" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-str nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-key" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-key nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-num" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-num nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-dec" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-dec nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvlt-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<text class="nj-jsonview-h" x="16" y="26" xml:space="preserve">basic_json::parse(): a tree, every array, object, and string in its own heap allocation</text>
<rect class="nj-jsonview-box" x="16" y="98" width="60" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="46" y="120" text-anchor="middle" xml:space="preserve">json</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M76 115 L106 115" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="108" y="98" width="84" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="150" y="120" text-anchor="middle" xml:space="preserve">std::map</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 L226 67" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="228" y="50" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="72" xml:space="preserve">&quot;port&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-num" x="396" y="72" text-anchor="end" xml:space="preserve">6379</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 L226 115" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="228" y="98" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="120" xml:space="preserve">&quot;price&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-num" x="396" y="120" text-anchor="end" xml:space="preserve">19.9</text>
<text class="nj-jsonview-note" x="418" y="120" xml:space="preserve">double: 19.90 is gone</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M192 115 L226 163" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="228" y="146" width="180" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-c-key" x="240" y="168" xml:space="preserve">&quot;tags&quot;</text>
<text class="nj-jsonview-mono nj-jsonview-c-line" x="396" y="168" text-anchor="end" xml:space="preserve">•</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M408 163 L442 163" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="444" y="146" width="104" height="34" rx="5"/>
<text class="nj-jsonview-mono" x="496" y="168" text-anchor="middle" xml:space="preserve">std::vector</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M548 163 L576 163" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="578" y="146" width="92" height="34" rx="5"/>
<path class="nj-jsonview-sep" d="M624 146 V180"/>
<text class="nj-jsonview-mono" x="601" y="168" text-anchor="middle" xml:space="preserve">json</text>
<text class="nj-jsonview-mono" x="647" y="168" text-anchor="middle" xml:space="preserve">json</text>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M601 146 C601 130 641 130 706 130" marker-end="url(#jvlt-line)"/>
<path class="nj-jsonview-arr nj-jsonview-c-line" d="M647 180 C647 196 687 196 706 196" marker-end="url(#jvlt-line)"/>
<rect class="nj-jsonview-heap" x="708" y="113" width="126" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-sm nj-jsonview-c-str" x="771" y="135" text-anchor="middle" xml:space="preserve">std::string eu</text>
<rect class="nj-jsonview-heap" x="708" y="179" width="126" height="34" rx="5"/>
<text class="nj-jsonview-mono nj-jsonview-sm nj-jsonview-c-str" x="771" y="201" text-anchor="middle" xml:space="preserve">std::string a&quot;b</text>
<rect class="nj-jsonview-heap" x="16" y="186" width="18" height="14" rx="3"/>
<text class="nj-jsonview-note" x="42" y="198" xml:space="preserve">a separate heap allocation</text>
</svg>

</div>

<p class="nj-caption" markdown>What `json::parse()` builds: a tree in which every object, array, and string is a
separate heap allocation (dashed). The float is converted to the nearest `double` while parsing, so the original text
`19.90` is gone: the stored value is 19.899999999999998578…, which `dump()` writes as `19.9`, the shortest text that
reads back as the same `double`.</p>

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-jsonview " viewBox="0 0 840 456" role="img" aria-labelledby="fig-jvli-title fig-jvli-title-d" xmlns="http://www.w3.org/2000/svg">
<title id="fig-jvli-title">The same J&#8203;SON text parsed by json_document::parse()</title>
<desc id="fig-jvli-title-d">The same text parsed by json_document::parse(): it keeps the 54 bytes of source text and builds a flat index of nine 16-byte nodes in document order: object, key port, unsigned integer 6379 (the converted value is in the node), key price, float, key tags, array, string eu, and an escaped string. Keys, the float, and the plain string point back into the source text; the escaped string points into the document&#x27;s buffer of decoded strings. A json_view is two pointers: one to the document and one to a node, here the array.</desc>
<defs>
<marker id="jvli-line" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-line nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-str" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-str nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-key" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-key nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-num" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-num nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-dec" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-dec nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-own" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-own nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-struct" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-struct nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
<marker id="jvli-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path class="nj-jsonview-c-bad nj-jsonview-head" d="M0 1 L10 5 L0 9 z"/></marker>
</defs>
<g transform="translate(0 -236)">
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
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M166 406 C166 367 98 367 98 328" marker-end="url(#jvli-key)"/>
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
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M342 406 C342 367 301 367 301 328" marker-end="url(#jvli-key)"/>
<rect class="nj-jsonview-node nj-jsonview-c-num" x="388" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="394" y="420" xml:space="preserve">4</text>
<text class="nj-jsonview-kind nj-jsonview-c-num" x="430" y="434" text-anchor="middle" xml:space="preserve">float</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="430" y="451" text-anchor="middle" xml:space="preserve">off 24</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="430" y="465" text-anchor="middle" xml:space="preserve">len 5</text>
<path class="nj-jsonview-arr nj-jsonview-c-num" d="M430 406 C430 367 413 367 413 328" marker-end="url(#jvli-num)"/>
<rect class="nj-jsonview-node nj-jsonview-c-key" x="476" y="406" width="84" height="68" rx="5"/>
<text class="nj-jsonview-tiny" x="482" y="420" xml:space="preserve">5</text>
<text class="nj-jsonview-kind nj-jsonview-c-key" x="518" y="434" text-anchor="middle" xml:space="preserve">key</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="518" y="451" text-anchor="middle" xml:space="preserve">off 32</text>
<text class="nj-jsonview-mono nj-jsonview-xs" x="518" y="465" text-anchor="middle" xml:space="preserve">len 4</text>
<path class="nj-jsonview-arr nj-jsonview-c-key" d="M518 406 C518 367 518 367 518 328" marker-end="url(#jvli-key)"/>
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
<path class="nj-jsonview-arr nj-jsonview-c-str" d="M694 406 C694 367 630 367 630 328" marker-end="url(#jvli-str)"/>
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
<path class="nj-jsonview-arr nj-jsonview-c-dec" d="M782 474 C782 496 773 496 773 518" marker-end="url(#jvli-dec)"/>
<text class="nj-jsonview-mono nj-jsonview-sm" x="470" y="670" text-anchor="end" xml:space="preserve">json_view v = doc.root()[&quot;tags&quot;]</text>
<rect class="nj-jsonview-node nj-jsonview-c-struct" x="480" y="648" width="140" height="34" rx="6"/>
<path class="nj-jsonview-sep" d="M550 648 V682"/>
<text class="nj-jsonview-mono" x="515" y="670" text-anchor="middle" xml:space="preserve">doc*</text>
<text class="nj-jsonview-mono" x="585" y="670" text-anchor="middle" xml:space="preserve">node*</text>
<path class="nj-jsonview-arr nj-jsonview-c-struct" d="M515 648 L515 622" marker-end="url(#jvli-struct)"/>
<path class="nj-jsonview-arr nj-jsonview-c-struct" d="M585 648 C585 561 606 561 606 474" marker-end="url(#jvli-struct)"/>
<text class="nj-jsonview-note" x="30" y="524" xml:space="preserve">integers are converted while parsing and kept in their node;</text>
<text class="nj-jsonview-note" x="30" y="542" xml:space="preserve">floats and strings point back into the text</text>
</g>
</svg>

</div>

<p class="nj-caption" markdown>What `json_document::parse()` builds from the same text: one flat index of nine 16-byte
nodes in document order, which point back into the source text, plus a buffer for the one string with an escape. A
`json_view` is two pointers, here to the array.</p>

### One flat index

The design is not ours either. [simdjson's tape](https://github.com/simdjson/simdjson/blob/master/doc/tape.md) and
[yyjson](https://github.com/ibireme/yyjson)'s immutable document are both flat arrays of fixed-size entries in document
order instead of trees of separate allocations, and yyjson's entries are 16 bytes, too. Ours:

```cpp
struct node
{
    node_kind     kind;    // object = 1, array = 2, string, number, ...
    std::uint8_t  flags;   // escaped, edited, moved, ...
    std::uint16_t extra;   // numbers: digits before and after the point; big objects: hash index
    std::uint32_t off;     // where the value starts in the source text (or in the arena)
    std::uint32_t len;     // strings and float tokens: bytes; containers: number of elements
    std::uint32_t next;    // containers: number of nodes in the subtree, including this one
};
static_assert(sizeof(node) == 16, "node must stay 16 bytes");
```

<p class="nj-code-caption" markdown>A node of `json_document`'s index: 16 bytes for every value.</p>

- **Skipping is an addition.** A container stores the size of its subtree, so the value after it is
  `n + (is_container(*n) ? n->next : 1)`, and the members of an object are a key node followed by the value's subtree.
  There are no pointers in the parsed index (edits add links, below); the parser fills in `next` when the container
  closes. `is_container()` is a single subtraction and comparison, `kind - 1u <= 1u`, which is why objects and arrays
  are numbered 1 and 2.
- **Strings stay in the input.** Only strings with escapes are decoded, into an arena. A document makes only a handful
  of allocations, no matter how many values it has. The price is that the text must outlive the document, unless the
  document owns it: [`parse_copy()`](../../api/basic_json_document/parse_copy.md) copies the text, and parsing an
  rvalue `std::string` moves it into the document. Input that can't be read as one contiguous block of bytes, such as a
  stream or a `FILE*`, is read into a buffer that the document owns, too. Offsets are 32 bits, which limits a document
  to 4 GiB.
- **Integers are converted while their digits are in the cache,** into the last 8 bytes of their node.
- **Floats stay text until you read them.** The node records the number of digits before and after the point, and
  reading converts with the same Clinger/Eisel-Lemire code as `json::parse`. We tried converting them during the parse.
  Although parsing `canada.json` and reading every number got 4–7% faster, parsing alone got 36–90% slower, so we
  dropped it. A default `dump()` writes the shortest form of a float, as `json` does;
  [`number_format::source`](../../api/basic_json_view/number_format.md) copies the source text of every number instead.
- **SIMD and tables** as in theme <a class="nj-theme" href="#theme-2" title="theme 2">2</a>, and `\u` escapes are
  decoded with a table, as in yyjson.
- **A hash index for big objects,** an idea from [Boost.JSON](https://github.com/boostorg/json). An object with 128 or
  more members gets an open-addressing table after parsing; looking up every key of a 10,000-member object went from
  59.8 ms to 0.16 ms. The hash is not seeded, so crafted keys could make building the table quadratic. Probing is
  therefore capped at 64 slots: a key that would need more drops the table, and that one object falls back to a linear
  search. Parsing can't become quadratic, and a lookup is never slower than the linear search of a small object.
- **Validating writes no index.** [`json_document::accept()`](../../api/basic_json_document/accept.md) runs a second
  instantiation of the same builder with a template parameter that turns every store off, so the checks are the same
  code, but no node is written and no escaped string is decoded. On x86-64 that made it 17–31% faster on `twitter.json`,
  `citm_catalog.json` and `canada.json`, and the 56 MB `jeopardy.json` no longer needs 52 MB of fresh memory just to be
  validated.
- **First duplicate wins.** Lookups return the first of duplicate keys, as yyjson and simdjson do, because returning the
  last one meant scanning every object to its end and made lookups in small objects 1.6–3.4× slower. `json::parse()`
  keeps the last one, so for a text with duplicate keys, the two can disagree; the documentation says so.

### It can be edited, too

A read-only index is the easy case, and a fair objection is that `json_document` is only fast because it can't change.
[`json_editable_document`](../../features/json_view/editing.md) has `set()`, `insert()`, `erase()` and
`push_back()`. An edit never writes into the source text and never moves the parsed index:

- a new scalar is written over its own node, with new string and number text in an append-only arena;
- new arrays and objects are allocated in chunks of nodes that never move;
- a container whose elements change is marked as moved and gets a separate list of its entries: links to the values,
  which stay where they are. The list doubles when it grows, so `push_back()` is amortized constant.

Views stay valid across edits, because values never move. Reading an edited container costs one flag test per container
and one test per element for a link. The link case is out of line, so that it compiles to a predicted branch rather than
a conditional select that would delay the following loads. Whereas a read-only document carries none of this, an
editable one that hasn't been edited reads within 2% of it on most rows and within 8% on the worst. And because
untouched values keep their source text, [`dump()`](../../api/basic_json_view/dump.md) with `number_format::source`
writes back a patched configuration file with its member order and the spelling of every number (`19.90`) intact, which
`json` (sorted keys) and `ordered_json` (`19.9`) can't.

The limits are documented: `set()` of a new key searches the object's members, so building a large object key by key is
quadratic, as with `ordered_json`, and an object that was edited loses its hash index and is searched linearly. [How it
compares](#how-it-compares) times the editable document against the mutable trees of other libraries.

## How it compares

"Which JSON library parses fastest?" has no answer, because "parsing" means different things in different libraries.
They hold a parsed JSON text in four different ways:

| approach | what you get | what it costs | libraries we measured |
| --- | --- | --- | --- |
| **mutable tree** | a value per JSON value, every string and number converted and owned; change anything | an allocation per container and often per string, all freed again | nlohmann/json `json`, [Boost.JSON](https://github.com/boostorg/json), [RapidJSON](https://github.com/Tencent/rapidjson), [sonic-cpp](https://github.com/bytedance/sonic-cpp), [Glaze](https://github.com/stephenberry/glaze) `generic`, [yyjson](https://github.com/ibireme/yyjson)'s mutable document; [serde_json](https://github.com/serde-rs/json), [sonic-rs](https://github.com/cloudwego/sonic-rs), [simd-json](https://github.com/simd-lite/simd-json) values |
| **flat document** | one array of small entries in document order; read in any order, many times | a few allocations; read-only, or extra bookkeeping to edit | nlohmann/json `json_document` (editable as `json_editable_document`), yyjson, [simdjson](https://github.com/simdjson/simdjson) DOM |
| **forward-only reading** | each value once, in document order: events (SAX) or a cursor | nothing is built; you can't go back | nlohmann/json [`sax_parse`](../../api/basic_json/sax_parse.md), RapidJSON `Reader`, Boost.JSON `basic_parser`, simdjson On-Demand, Glaze `lazy_json`; serde visitors in Rust |
| **into your own types** | the fields you declared, nothing else | a struct per document shape; other fields are skipped | Glaze reading into structs, serde with `derive`, nlohmann/json `from_json()` from `json` or from a view |

<p class="nj-table-caption" markdown>The kinds of representation the libraries in this comparison offer. Most libraries
offer more than one.</p>

So a comparison of parse times across the rows of this table compares different amounts of work. Instead, we compare
**use cases**: tasks a program actually has, each of which every library may solve in whatever way it does best. In
nlohmann/json, `json` is the mutable tree and `json_document` the flat document, so we show the library twice: its best
way *with* `json_document` and its best way *without* it.

### Six use cases

Each starts from the file's text in a `std::string` (or a byte slice in Rust) and ends with everything the library built
freed again:

- **validate:** is this text valid JSON? Nothing is kept, so this measures the parser alone, as in a server that checks
  a request before it passes it on.
- **sum:** visit every value in document order, convert every number, and add them up. This measures walking a whole
  document and converting all of its numbers.
- **select:** read a few fields of every record, such as the id, the user name, and the retweet count of every tweet, as
  a program does that needs only part of a response. A library that reads lazily can skip the rest.
- **edit:** change a value, remove a member, and add a member in every record, then write the result as compact JSON:
  the round trip of a program that patches a message or a configuration.
- **minify:** read the text and write it as compact JSON, without whitespace. This measures reading and writing
  together, without changes in between.
- **write:** write a document that was parsed beforehand as compact JSON; only the writing is timed.

Each use case runs on each of the four test files, and each library may solve it in every way it offers: in place, with
a SAX handler, into structs, with a parser that is reused (measured, but not chosen). Before anything is timed, every
way's result is checked: the same values, the same string bytes, the same sum of all numbers (to the last bit where they
are added in the same order), and an output that reads back as the expected document. The [README of the
programs](https://github.com/nlohmann/json/tree/develop/tests/benchmarks/json_view/others) lists every way, the fields
and edits per file, and the checks.

### Where the input comes from

Starting from a string in memory is how most JSON benchmarks work: it measures the library, not the disk or the
operating system. It is not neutral in every detail, though:

- The string has 64 bytes of spare capacity, so simdjson, which reads up to 64 bytes past the end, can use it without a
  copy. A program would load the file into such a buffer in the first place.
- yyjson, RapidJSON, and simd-json can parse in place, which changes the buffer. So every call gets a fresh copy of the
  string, and the copy counts toward their time: 11–14 µs for `twitter.json` on the Mac, and 30–46 µs on x86-64, where
  fresh memory costs page faults. yyjson's normal read makes the same copy internally, which is why both ways take about
  as long. A server that validates a request and then passes it on needs the copy. A program that reads a file into a
  buffer it owns can skip it, so we also timed the in-place ways with the copy made before the timer starts. On the Mac,
  yyjson then comes 3–5% closer, and on `twitter.json` it validates and selects 1–2% faster than `json_document`. On
  x86-64, it ties `json_document` in *sum* with Clang and takes 1.04× and 1.15× its time with GCC 16 and GCC 13.
- `json_document` reads the string in place and keeps pointing into it. A document that owns its text
  ([`parse_copy()`](../../api/basic_json_document/parse_copy.md)) costs one copy more: 3–5% on the Mac.
- Reading from files and streams is not part of the comparison.

```mermaid
flowchart TB
    f[/"test file"/] -->|"read once, untimed"| s["std::string with 64 spare bytes"]
    s --> timed
    subgraph timed ["timed, every call"]
        direction LR
        c["copy<br>(in-place ways)"] --> p["parse"] --> u["use case"] --> d["free<br>everything"]
    end
```

<p class="nj-caption" markdown>What one timed call of a use case contains. For *write*, the document is parsed before
the timer starts, so only the writing is timed. Every way's result is checked before anything is timed.</p>

### Checking less, on purpose

Some libraries can skip parts of the validation, and that is often why they are fast. A lazy reader such as simdjson's
On-Demand API or Glaze's `lazy_json` only looks at what you ask for; to step over the rest, it matches brackets without
looking inside, so reading a few fields of a large record costs little more than finding them. A minifier only needs to
find whitespace, not understand the values. Skipping the UTF-8 check is RapidJSON's default and sonic-cpp's too. Each is
a good choice for input that is known to be valid, for example text your own program wrote a moment ago. To tell these
ways apart, every way is also fed four broken inputs: the file cut short by one byte, a stray comma, an invalid UTF-8
byte in a string, and garbage after the value. A way that rejects all four validates fully, and each cell shows the
fastest such way. A way that checks or does less appears in the right half of the cell, with a letter that the caption
explains.

A word on who set the rules: we wrote every library's benchmark code, chose the files and the rules, and tuned 3.13.0 on
the same machines and files. No maintainer of the other libraries has reviewed their code. If you know a faster way for
any of them, please open an issue, and we will rerun the comparison. To check ourselves, we also ran files and a
conformance suite we never tuned on ([below](#files-and-checks-we-didnt-choose)).

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog nj-charts--heat" viewBox="0 0 784 510" role="img" aria-labelledby="nj-blog-uc-mac nj-blog-uc-mac-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-uc-mac">Use cases: time of each library relative to the fastest, Apple M1 Max</title>
<desc id="nj-blog-uc-mac-d">Table of relative times, libraries by use case. nlohmann/json json_document validate: 1.00; nlohmann/json json_document sum: 1.00; nlohmann/json json_document select: 1.00; nlohmann/json json_document edit: 1.00 (0.85 doing less, N); nlohmann/json json_document minify: 1.00 (0.84 doing less, N); nlohmann/json json_document write: 1.00 (0.69 doing less, N); yyjson validate: 1.41; yyjson sum: 1.14; yyjson select: 1.30; yyjson edit: 1.48; yyjson minify: 1.26 (1.18 doing less, N); yyjson write: 1.23; simdjson validate: 1.52; simdjson sum: 1.21; simdjson select: 1.34 (0.76 doing less, P); simdjson edit: n/a; simdjson minify: 1.73 (0.18 doing less, P); simdjson write: 2.41; sonic-rs (Rust) validate: 1.91; sonic-rs (Rust) sum: 1.54; sonic-rs (Rust) select: 1.85; sonic-rs (Rust) edit: 2.10; sonic-rs (Rust) minify: 1.93; sonic-rs (Rust) write: 2.34; sonic-cpp validate: no fully validating way (2.50 doing less, U); sonic-cpp sum: no fully validating way (1.86 doing less, U); sonic-cpp select: no fully validating way (2.34 doing less, U); sonic-cpp edit: no fully validating way (1.70 doing less, U); sonic-cpp minify: no fully validating way (2.03 doing less, U); sonic-cpp write: 1.61; simd-json (Rust) validate: 2.05; simd-json (Rust) sum: 1.63; simd-json (Rust) select: 2.39; simd-json (Rust) edit: 2.85; simd-json (Rust) minify: 3.40; simd-json (Rust) write: 3.05; nlohmann/json json validate: 1.38; nlohmann/json json sum: 1.34; nlohmann/json json select: 6.09; nlohmann/json json edit: 3.22; nlohmann/json json minify: 4.39; nlohmann/json json write: 2.03; Glaze validate: 2.03; Glaze sum: 3.88; Glaze select: 1.81 (0.81 doing less, P); Glaze edit: 4.44; Glaze minify: 5.23 (1.05 doing less, P); Glaze write: 2.19; Boost.J&#8203;SON validate: 2.54; Boost.J&#8203;SON sum: 2.02; Boost.J&#8203;SON select: 3.31; Boost.J&#8203;SON edit: 3.23; Boost.J&#8203;SON minify: 3.89; Boost.J&#8203;SON write: 3.67; serde_json (Rust) validate: 2.44 (2.21 doing less, U); serde_json (Rust) sum: 2.60; serde_json (Rust) select: 2.41 (2.26 doing less, U); serde_json (Rust) edit: 5.02; serde_json (Rust) minify: 5.85; serde_json (Rust) write: 2.90; RapidJSON validate: 4.67 (3.09 doing less, U); RapidJSON sum: 4.18 (2.89 doing less, U); RapidJSON select: 6.02 (3.93 doing less, U); RapidJSON edit: 4.85 (3.83 doing less, U); RapidJSON minify: 4.85 (3.66 doing less, U N); RapidJSON write: 5.74.</desc>
<text class="nj-charts-tick" x="270" y="34">validate</text>
<text class="nj-charts-tick" x="362" y="34">sum</text>
<text class="nj-charts-tick" x="454" y="34">select</text>
<text class="nj-charts-tick" x="546" y="34">edit</text>
<text class="nj-charts-tick" x="638" y="34">minify</text>
<text class="nj-charts-tick" x="730" y="34">write</text>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="66" text-anchor="end">nlohmann/json json_document</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · validate&#10;1.00× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 172 µs&#10;citm_catalog.json: 313 µs&#10;canada.json: 905 µs&#10;jeopardy.json: 20,926 µs">
<rect class="nj-heat-0" x="225" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · sum&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 219 µs&#10;citm_catalog.json: 493 µs&#10;canada.json: 1,803 µs&#10;jeopardy.json: 28,898 µs">
<rect class="nj-heat-0" x="317" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · select&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 183 µs&#10;citm_catalog.json: 363 µs&#10;canada.json: 944 µs&#10;jeopardy.json: 24,801 µs">
<rect class="nj-heat-0" x="409" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit&#10;1.00× the time of the fastest library (fully validating)&#10;way: editable&#10;twitter.json: 288 µs&#10;citm_catalog.json: 559 µs&#10;canada.json: 2,737 µs&#10;jeopardy.json: 58,019 µs">
<rect class="nj-heat-0" x="501" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit, checking less&#10;0.85× the time of the fastest fully validating library&#10;way: editable (source numbers)&#10;twitter.json: 281 µs (validates fully)&#10;citm_catalog.json: 557 µs (validates fully)&#10;canada.json: 1,504 µs (validates fully)&#10;jeopardy.json: 57,885 µs (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="547" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="60" text-anchor="middle">0.85</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 261 µs&#10;citm_catalog.json: 496 µs&#10;canada.json: 2,570 µs&#10;jeopardy.json: 37,624 µs">
<rect class="nj-heat-0" x="593" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify, checking less&#10;0.84× the time of the fastest fully validating library&#10;twitter.json: 252 µs · parse + dump (source numbers) (validates fully)&#10;citm_catalog.json: 494 µs · parse + dump (source numbers) (validates fully)&#10;canada.json: 1,343 µs · parse + dump (source numbers) (validates fully)&#10;jeopardy.json: 37,624 µs · parse + dump (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="639" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="60" text-anchor="middle">0.84</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write&#10;1.00× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 76.2 µs&#10;citm_catalog.json: 139 µs&#10;canada.json: 1,625 µs&#10;jeopardy.json: 14,861 µs">
<rect class="nj-heat-0" x="685" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="707.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write, checking less&#10;0.69× the time of the fastest fully validating library&#10;way: dump (source numbers)&#10;twitter.json: 72.8 µs (validates fully)&#10;citm_catalog.json: 136 µs (validates fully)&#10;canada.json: 398 µs (validates fully)&#10;jeopardy.json: 14,758 µs (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="731" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="752.5" y="60" text-anchor="middle">0.69</text>
<text class="nj-charts-cell nj-charts-cell--small" x="752.5" y="73" text-anchor="middle">N</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="102" text-anchor="end">yyjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · validate&#10;1.41× the time of the fastest library (fully validating)&#10;twitter.json: 183 µs · insitu (copy)&#10;citm_catalog.json: 476 µs · read&#10;canada.json: 1,487 µs · insitu (copy)&#10;jeopardy.json: 30,922 µs · read&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="225" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="102" text-anchor="middle">1.41</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · sum&#10;1.14× the time of the fastest library (fully validating)&#10;twitter.json: 231 µs · insitu (copy)&#10;citm_catalog.json: 571 µs · read&#10;canada.json: 1,875 µs · read&#10;jeopardy.json: 37,817 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-0" x="317" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="102" text-anchor="middle">1.14</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · select&#10;1.30× the time of the fastest library (fully validating)&#10;twitter.json: 191 µs · insitu (copy)&#10;citm_catalog.json: 480 µs · read&#10;canada.json: 1,489 µs · insitu (copy)&#10;jeopardy.json: 32,777 µs · read (raw numbers)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="409" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="102" text-anchor="middle">1.30</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · edit&#10;1.48× the time of the fastest library (fully validating)&#10;twitter.json: 440 µs · insitu (copy) + mut copy&#10;citm_catalog.json: 904 µs · mut copy&#10;canada.json: 3,692 µs · mut copy&#10;jeopardy.json: 84,466 µs · insitu (copy) + mut copy&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="501" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="102" text-anchor="middle">1.48</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify&#10;1.26× the time of the fastest library (fully validating)&#10;twitter.json: 298 µs · insitu (copy) + write&#10;citm_catalog.json: 642 µs · read + write&#10;canada.json: 3,222 µs · insitu (copy) + write&#10;jeopardy.json: 51,001 µs · read + write&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="593" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="102" text-anchor="middle">1.26</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify, checking less&#10;1.18× the time of the fastest fully validating library&#10;twitter.json: 298 µs · insitu (copy) + write (validates fully)&#10;citm_catalog.json: 642 µs · read + write (validates fully)&#10;canada.json: 2,523 µs · read (raw numbers) + write (validates fully)&#10;jeopardy.json: 51,001 µs · read + write (validates fully)&#10;copies each number&#x27;s text instead of formatting it (YYJSON_READ_NUMBER_AS_RAW)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="639" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="96" text-anchor="middle">1.18</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="109" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · write&#10;1.23× the time of the fastest library (fully validating)&#10;way: write&#10;twitter.json: 101 µs&#10;citm_catalog.json: 167 µs&#10;canada.json: 1,719 µs&#10;jeopardy.json: 19,937 µs">
<rect class="nj-heat-1" x="685" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="102" text-anchor="middle">1.23</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="138" text-anchor="end">simdjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · validate&#10;1.52× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 215 µs&#10;citm_catalog.json: 460 µs&#10;canada.json: 1,890 µs&#10;jeopardy.json: 28,890 µs">
<rect class="nj-heat-2" x="225" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="138" text-anchor="middle">1.52</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · sum&#10;1.21× the time of the fastest library (fully validating)&#10;twitter.json: 249 µs · D&#8203;OM&#10;citm_catalog.json: 572 µs · On-Demand&#10;canada.json: 2,398 µs · On-Demand&#10;jeopardy.json: 34,994 µs · D&#8203;OM">
<rect class="nj-heat-1" x="317" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="138" text-anchor="middle">1.21</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select&#10;1.34× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 192 µs&#10;citm_catalog.json: 454 µs&#10;canada.json: 1,893 µs&#10;jeopardy.json: 30,714 µs">
<rect class="nj-heat-1" x="409" y="117" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="138" text-anchor="middle">1.34</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select, checking less&#10;0.76× the time of the fastest fully validating library&#10;twitter.json: 128 µs · On-Demand structs&#10;citm_catalog.json: 356 µs · On-Demand&#10;canada.json: 571 µs · On-Demand&#10;jeopardy.json: 19,633 µs · On-Demand&#10;reads lazily: On-Demand reads only what you ask for and steps over the rest by matching brackets">
<rect class="nj-heat-0" x="455" y="117" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="132" text-anchor="middle">0.76</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="145" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · edit&#10;simdjson&#x27;s documents are read-only: it has no A&#8203;PI to change a value and write the result">
<rect class="nj-heat-na" x="501" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-tick" x="546" y="138">n/a</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify&#10;1.73× the time of the fastest library (fully validating)&#10;way: D&#8203;OM + to_string&#10;twitter.json: 425 µs&#10;citm_catalog.json: 850 µs&#10;canada.json: 5,094 µs&#10;jeopardy.json: 61,202 µs">
<rect class="nj-heat-2" x="593" y="117" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="138" text-anchor="middle">1.73</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify, checking less&#10;0.18× the time of the fastest fully validating library&#10;way: minify&#10;twitter.json: 62.5 µs&#10;citm_catalog.json: 168 µs&#10;canada.json: 227 µs&#10;jeopardy.json: 5,756 µs&#10;simdjson::minify() only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="117" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="132" text-anchor="middle">0.18</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="145" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · write&#10;2.41× the time of the fastest library (fully validating)&#10;way: to_string&#10;twitter.json: 201 µs&#10;citm_catalog.json: 416 µs&#10;canada.json: 3,186 µs&#10;jeopardy.json: 32,185 µs">
<rect class="nj-heat-2" x="685" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="138" text-anchor="middle">2.41</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="174" text-anchor="end">sonic-rs (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · validate&#10;1.91× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 326 µs&#10;citm_catalog.json: 681 µs&#10;canada.json: 1,939 µs&#10;jeopardy.json: 31,450 µs">
<rect class="nj-heat-2" x="225" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="174" text-anchor="middle">1.91</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · sum&#10;1.54× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 364 µs&#10;citm_catalog.json: 778 µs&#10;canada.json: 2,703 µs&#10;jeopardy.json: 41,361 µs">
<rect class="nj-heat-2" x="317" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="174" text-anchor="middle">1.54</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · select&#10;1.85× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 333 µs&#10;citm_catalog.json: 691 µs&#10;canada.json: 1,936 µs&#10;jeopardy.json: 40,660 µs">
<rect class="nj-heat-2" x="409" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="174" text-anchor="middle">1.85</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · edit&#10;2.10× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 634 µs&#10;citm_catalog.json: 1,257 µs&#10;canada.json: 4,396 µs&#10;jeopardy.json: 140,936 µs">
<rect class="nj-heat-2" x="501" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="174" text-anchor="middle">2.10</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · minify&#10;1.93× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 535 µs&#10;citm_catalog.json: 1,134 µs&#10;canada.json: 4,377 µs&#10;jeopardy.json: 64,832 µs">
<rect class="nj-heat-2" x="593" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="174" text-anchor="middle">1.93</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · write&#10;2.34× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 212 µs&#10;citm_catalog.json: 446 µs&#10;canada.json: 2,419 µs&#10;jeopardy.json: 33,366 µs">
<rect class="nj-heat-2" x="685" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="174" text-anchor="middle">2.34</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="210" text-anchor="end">sonic-cpp</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · validate, checking less&#10;2.50× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 382 µs&#10;citm_catalog.json: 985 µs&#10;canada.json: 2,579 µs&#10;jeopardy.json: 40,996 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="225" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="204" text-anchor="middle">2.50</text>
<text class="nj-charts-cell nj-charts-cell--small" x="270" y="217" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · sum, checking less&#10;1.86× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 428 µs&#10;citm_catalog.json: 1,098 µs&#10;canada.json: 2,975 µs&#10;jeopardy.json: 48,487 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="317" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="204" text-anchor="middle">1.86</text>
<text class="nj-charts-cell nj-charts-cell--small" x="362" y="217" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · select, checking less&#10;2.34× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 385 µs&#10;citm_catalog.json: 993 µs&#10;canada.json: 2,611 µs&#10;jeopardy.json: 46,356 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="409" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="204" text-anchor="middle">2.34</text>
<text class="nj-charts-cell nj-charts-cell--small" x="454" y="217" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · edit, checking less&#10;1.70× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 488 µs&#10;citm_catalog.json: 1,218 µs&#10;canada.json: 5,662 µs&#10;jeopardy.json: 63,697 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="501" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="204" text-anchor="middle">1.70</text>
<text class="nj-charts-cell nj-charts-cell--small" x="546" y="217" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · minify, checking less&#10;2.03× the time of the fastest fully validating library&#10;way: Document + Serialize&#10;twitter.json: 504 µs&#10;citm_catalog.json: 1,217 µs&#10;canada.json: 5,634 µs&#10;jeopardy.json: 61,988 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="593" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="204" text-anchor="middle">2.03</text>
<text class="nj-charts-cell nj-charts-cell--small" x="638" y="217" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · write&#10;1.61× the time of the fastest library (fully validating)&#10;way: Serialize&#10;twitter.json: 114 µs&#10;citm_catalog.json: 240 µs&#10;canada.json: 3,109 µs&#10;jeopardy.json: 20,327 µs">
<rect class="nj-heat-2" x="685" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="210" text-anchor="middle">1.61</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="246" text-anchor="end">simd-json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · validate&#10;2.05× the time of the fastest library (fully validating)&#10;way: tape (copy)&#10;twitter.json: 289 µs&#10;citm_catalog.json: 698 µs&#10;canada.json: 2,278 µs&#10;jeopardy.json: 38,874 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="225" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="246" text-anchor="middle">2.05</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · sum&#10;1.63× the time of the fastest library (fully validating)&#10;way: visitor (copy)&#10;twitter.json: 354 µs&#10;citm_catalog.json: 866 µs&#10;canada.json: 2,717 µs&#10;jeopardy.json: 47,518 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="317" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="246" text-anchor="middle">1.63</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · select&#10;2.39× the time of the fastest library (fully validating)&#10;way: structs (copy)&#10;twitter.json: 364 µs&#10;citm_catalog.json: 914 µs&#10;canada.json: 2,657 µs&#10;jeopardy.json: 57,697 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="409" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="246" text-anchor="middle">2.39</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · edit&#10;2.85× the time of the fastest library (fully validating)&#10;way: borrowed (copy)&#10;twitter.json: 948 µs&#10;citm_catalog.json: 2,102 µs&#10;canada.json: 7,654 µs&#10;jeopardy.json: 110,693 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="246" text-anchor="middle">2.85</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · minify&#10;3.40× the time of the fastest library (fully validating)&#10;way: borrowed (copy)&#10;twitter.json: 952 µs&#10;citm_catalog.json: 2,111 µs&#10;canada.json: 7,658 µs&#10;jeopardy.json: 108,130 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="593" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="246" text-anchor="middle">3.40</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · write&#10;3.05× the time of the fastest library (fully validating)&#10;way: borrowed&#10;twitter.json: 355 µs&#10;citm_catalog.json: 478 µs&#10;canada.json: 2,728 µs&#10;jeopardy.json: 47,412 µs">
<rect class="nj-heat-3" x="685" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="246" text-anchor="middle">3.05</text>
</g>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="282" text-anchor="end">nlohmann/json json</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · validate&#10;1.38× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 234 µs&#10;citm_catalog.json: 456 µs&#10;canada.json: 1,253 µs&#10;jeopardy.json: 27,563 µs">
<rect class="nj-heat-1" x="225" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="282" text-anchor="middle">1.38</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · sum&#10;1.34× the time of the fastest library (fully validating)&#10;way: sax&#10;twitter.json: 303 µs&#10;citm_catalog.json: 602 µs&#10;canada.json: 2,208 µs&#10;jeopardy.json: 44,688 µs">
<rect class="nj-heat-1" x="317" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="282" text-anchor="middle">1.34</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · select&#10;6.09× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 1,208 µs&#10;citm_catalog.json: 2,128 µs&#10;canada.json: 5,088 µs&#10;jeopardy.json: 163,712 µs">
<rect class="nj-heat-4" x="409" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="282" text-anchor="middle">6.09</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · edit&#10;3.22× the time of the fastest library (fully validating)&#10;twitter.json: 1,115 µs · ordered_json&#10;citm_catalog.json: 2,065 µs · ordered_json&#10;canada.json: 7,348 µs · parse&#10;jeopardy.json: 162,216 µs · ordered_json">
<rect class="nj-heat-3" x="501" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="282" text-anchor="middle">3.22</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · minify&#10;4.39× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 1,446 µs&#10;citm_catalog.json: 2,406 µs&#10;canada.json: 7,328 µs&#10;jeopardy.json: 182,132 µs">
<rect class="nj-heat-3" x="593" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="282" text-anchor="middle">4.39</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · write&#10;2.03× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 216 µs&#10;citm_catalog.json: 287 µs&#10;canada.json: 2,274 µs&#10;jeopardy.json: 30,928 µs">
<rect class="nj-heat-2" x="685" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="282" text-anchor="middle">2.03</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="318" text-anchor="end">Glaze</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · validate&#10;2.03× the time of the fastest library (fully validating)&#10;way: validate_json&#10;twitter.json: 333 µs&#10;citm_catalog.json: 854 µs&#10;canada.json: 1,302 µs&#10;jeopardy.json: 46,251 µs">
<rect class="nj-heat-2" x="225" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="318" text-anchor="middle">2.03</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum&#10;3.88× the time of the fastest library (fully validating)&#10;way: generic (double, strict)&#10;twitter.json: 974 µs&#10;citm_catalog.json: 2,057 µs&#10;canada.json: 6,338 µs&#10;jeopardy.json: 100,272 µs">
<rect class="nj-heat-3" x="317" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="318" text-anchor="middle">3.88</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select&#10;1.81× the time of the fastest library (fully validating)&#10;way: structs (validate_skipped)&#10;twitter.json: 314 µs&#10;citm_catalog.json: 852 µs&#10;canada.json: 1,303 µs&#10;jeopardy.json: 47,692 µs">
<rect class="nj-heat-2" x="409" y="297" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="318" text-anchor="middle">1.81</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select, checking less&#10;0.81× the time of the fastest fully validating library&#10;way: structs&#10;twitter.json: 238 µs&#10;citm_catalog.json: 253 µs&#10;canada.json: 310 µs&#10;jeopardy.json: 36,013 µs&#10;reads into structs and steps over fields it doesn&#x27;t know without checking them (validate_skipped checks them too)">
<rect class="nj-heat-0" x="455" y="297" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="312" text-anchor="middle">0.81</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="325" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · edit&#10;4.44× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 1,527 µs&#10;citm_catalog.json: 3,216 µs&#10;canada.json: 11,033 µs&#10;jeopardy.json: 183,648 µs">
<rect class="nj-heat-3" x="501" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="318" text-anchor="middle">4.44</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify&#10;5.23× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 1,512 µs&#10;citm_catalog.json: 3,245 µs&#10;canada.json: 11,112 µs&#10;jeopardy.json: 172,173 µs">
<rect class="nj-heat-4" x="593" y="297" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="318" text-anchor="middle">5.23</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify, checking less&#10;1.05× the time of the fastest fully validating library&#10;way: minify_json&#10;twitter.json: 284 µs&#10;citm_catalog.json: 747 µs&#10;canada.json: 1,746 µs&#10;jeopardy.json: 40,439 µs&#10;minify_json only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="297" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="312" text-anchor="middle">1.05</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="325" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · write&#10;2.19× the time of the fastest library (fully validating)&#10;twitter.json: 212 µs · generic&#10;citm_catalog.json: 476 µs · generic (strict)&#10;canada.json: 1,702 µs · generic (strict)&#10;jeopardy.json: 34,032 µs · generic">
<rect class="nj-heat-2" x="685" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="318" text-anchor="middle">2.19</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="354" text-anchor="end">Boost.J&#8203;SON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · validate&#10;2.54× the time of the fastest library (fully validating)&#10;way: S&#8203;AX (numbers: none)&#10;twitter.json: 540 µs&#10;citm_catalog.json: 990 µs&#10;canada.json: 1,449 µs&#10;jeopardy.json: 54,480 µs">
<rect class="nj-heat-3" x="225" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="354" text-anchor="middle">2.54</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · sum&#10;2.02× the time of the fastest library (fully validating)&#10;way: S&#8203;AX&#10;twitter.json: 538 µs&#10;citm_catalog.json: 1,028 µs&#10;canada.json: 3,084 µs&#10;jeopardy.json: 54,765 µs">
<rect class="nj-heat-2" x="317" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="354" text-anchor="middle">2.02</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · select&#10;3.31× the time of the fastest library (fully validating)&#10;twitter.json: 623 µs · parse_into structs&#10;citm_catalog.json: 1,208 µs · parse_into structs&#10;canada.json: 3,638 µs · parse&#10;jeopardy.json: 67,923 µs · parse_into structs">
<rect class="nj-heat-3" x="409" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="354" text-anchor="middle">3.31</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · edit&#10;3.23× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 1,355 µs&#10;citm_catalog.json: 1,997 µs&#10;canada.json: 6,522 µs&#10;jeopardy.json: 157,849 µs">
<rect class="nj-heat-3" x="501" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="354" text-anchor="middle">3.23</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · minify&#10;3.89× the time of the fastest library (fully validating)&#10;way: parse + serialize&#10;twitter.json: 1,407 µs&#10;citm_catalog.json: 2,003 µs&#10;canada.json: 6,555 µs&#10;jeopardy.json: 154,865 µs">
<rect class="nj-heat-3" x="593" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="354" text-anchor="middle">3.89</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · write&#10;3.67× the time of the fastest library (fully validating)&#10;way: serialize&#10;twitter.json: 499 µs&#10;citm_catalog.json: 511 µs&#10;canada.json: 2,873 µs&#10;jeopardy.json: 63,201 µs">
<rect class="nj-heat-3" x="685" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="354" text-anchor="middle">3.67</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="390" text-anchor="end">serde_json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate&#10;2.44× the time of the fastest library (fully validating)&#10;way: from_utf8 + IgnoredAny&#10;twitter.json: 452 µs&#10;citm_catalog.json: 1,103 µs&#10;canada.json: 1,556 µs&#10;jeopardy.json: 46,517 µs">
<rect class="nj-heat-2" x="225" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="390" text-anchor="middle">2.44</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate, checking less&#10;2.21× the time of the fastest fully validating library&#10;way: IgnoredAny&#10;twitter.json: 354 µs&#10;citm_catalog.json: 1,047 µs&#10;canada.json: 1,451 µs&#10;jeopardy.json: 44,984 µs&#10;trusts U&#8203;TF-8 in the strings it skips (from_slice); strings it reads are checked">
<rect class="nj-heat-2" x="271" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="384" text-anchor="middle">2.21</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · sum&#10;2.60× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 652 µs&#10;citm_catalog.json: 1,242 µs&#10;canada.json: 4,772 µs&#10;jeopardy.json: 66,568 µs">
<rect class="nj-heat-3" x="317" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="390" text-anchor="middle">2.60</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · select&#10;2.41× the time of the fastest library (fully validating)&#10;way: from_utf8 + structs&#10;twitter.json: 480 µs&#10;citm_catalog.json: 1,125 µs&#10;canada.json: 1,560 µs&#10;jeopardy.json: 62,378 µs">
<rect class="nj-heat-2" x="409" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="390" text-anchor="middle">2.41</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · select, checking less&#10;2.26× the time of the fastest fully validating library&#10;twitter.json: 410 µs · structs&#10;citm_catalog.json: 1,084 µs · structs&#10;canada.json: 1,455 µs · structs&#10;jeopardy.json: 62,378 µs · from_utf8 + structs (validates fully)&#10;trusts U&#8203;TF-8 in the strings it skips (from_slice); strings it reads are checked">
<rect class="nj-heat-2" x="455" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="384" text-anchor="middle">2.26</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · edit&#10;5.02× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 2,009 µs&#10;citm_catalog.json: 3,316 µs&#10;canada.json: 9,666 µs&#10;jeopardy.json: 251,931 µs">
<rect class="nj-heat-4" x="501" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="390" text-anchor="middle">5.02</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · minify&#10;5.85× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 2,004 µs&#10;citm_catalog.json: 3,290 µs&#10;canada.json: 9,792 µs&#10;jeopardy.json: 227,369 µs">
<rect class="nj-heat-4" x="593" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="390" text-anchor="middle">5.85</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · write&#10;2.90× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 322 µs&#10;citm_catalog.json: 490 µs&#10;canada.json: 2,286 µs&#10;jeopardy.json: 49,967 µs">
<rect class="nj-heat-3" x="685" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="390" text-anchor="middle">2.90</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="426" text-anchor="end">RapidJSON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate&#10;4.67× the time of the fastest library (fully validating)&#10;twitter.json: 1,318 µs · insitu (copy)&#10;citm_catalog.json: 1,391 µs · S&#8203;AX (string stream, default precision)&#10;canada.json: 1,971 µs · S&#8203;AX (string stream, default precision)&#10;jeopardy.json: 133,695 µs · S&#8203;AX (string stream, default precision)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="426" text-anchor="middle">4.67</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate, checking less&#10;3.09× the time of the fastest fully validating library&#10;twitter.json: 706 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,033 µs · S&#8203;AX (string stream, default precision) (no encoding check)&#10;canada.json: 1,971 µs · S&#8203;AX (string stream, default precision) (validates fully)&#10;jeopardy.json: 64,732 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="271" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="420" text-anchor="middle">3.09</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum&#10;4.18× the time of the fastest library (fully validating)&#10;twitter.json: 1,332 µs · S&#8203;AX&#10;citm_catalog.json: 1,472 µs · S&#8203;AX (string stream)&#10;canada.json: 6,448 µs · S&#8203;AX (string stream)&#10;jeopardy.json: 136,330 µs · S&#8203;AX (string stream)">
<rect class="nj-heat-3" x="317" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="426" text-anchor="middle">4.18</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum, checking less&#10;2.89× the time of the fastest fully validating library&#10;twitter.json: 738 µs · S&#8203;AX (string stream) (no encoding check)&#10;citm_catalog.json: 1,157 µs · S&#8203;AX (string stream) (no encoding check)&#10;canada.json: 6,432 µs · S&#8203;AX (string stream) (no encoding check)&#10;jeopardy.json: 71,646 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="363" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="420" text-anchor="middle">2.89</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select&#10;6.02× the time of the fastest library (fully validating)&#10;twitter.json: 1,314 µs · insitu (copy)&#10;citm_catalog.json: 1,578 µs · insitu (copy)&#10;canada.json: 6,814 µs · Document (string stream)&#10;jeopardy.json: 144,649 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-4" x="409" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="426" text-anchor="middle">6.02</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select, checking less&#10;3.93× the time of the fastest fully validating library&#10;twitter.json: 701 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,166 µs · insitu (copy) (no encoding check)&#10;canada.json: 6,745 µs · Document (string stream) (no encoding check)&#10;jeopardy.json: 67,617 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="455" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="420" text-anchor="middle">3.93</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit&#10;4.85× the time of the fastest library (fully validating)&#10;twitter.json: 1,924 µs · Document&#10;citm_catalog.json: 2,393 µs · insitu (copy)&#10;canada.json: 13,711 µs · Document (string stream)&#10;jeopardy.json: 224,328 µs · Document (string stream)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="426" text-anchor="middle">4.85</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit, checking less&#10;3.83× the time of the fastest fully validating library&#10;twitter.json: 1,356 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,992 µs · insitu (copy) (no encoding check)&#10;canada.json: 13,711 µs · Document (string stream) (validates fully)&#10;jeopardy.json: 147,902 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="547" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="420" text-anchor="middle">3.83</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify&#10;4.85× the time of the fastest library (fully validating)&#10;twitter.json: 1,523 µs · S&#8203;AX to Writer&#10;citm_catalog.json: 1,803 µs · S&#8203;AX to Writer (string stream)&#10;canada.json: 14,378 µs · Document + Writer&#10;jeopardy.json: 174,958 µs · S&#8203;AX to Writer (string stream)">
<rect class="nj-heat-3" x="593" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="426" text-anchor="middle">4.85</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify, checking less&#10;3.66× the time of the fastest fully validating library&#10;twitter.json: 1,044 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;citm_catalog.json: 1,499 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;canada.json: 11,568 µs · S&#8203;AX to Writer (raw numbers) (validates fully)&#10;jeopardy.json: 123,908 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;copies each number&#x27;s text instead of formatting it (kParseNumbersAsStringsFlag)">
<rect class="nj-heat-3" x="639" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="420" text-anchor="middle">3.66</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="433" text-anchor="middle">U N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · write&#10;5.74× the time of the fastest library (fully validating)&#10;way: Writer&#10;twitter.json: 596 µs&#10;citm_catalog.json: 836 µs&#10;canada.json: 6,928 µs&#10;jeopardy.json: 80,160 µs">
<rect class="nj-heat-4" x="685" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="426" text-anchor="middle">5.74</text>
</g>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="472">time relative to the fastest fully validating library, less is better</text>
<g><rect class="nj-heat-0" x="8" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="46" y="496" text-anchor="middle">below 1.15</text></g>
<g><rect class="nj-heat-1" x="88" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="126" y="496" text-anchor="middle">1.15 to 1.5</text></g>
<g><rect class="nj-heat-2" x="168" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="206" y="496" text-anchor="middle">1.5 to 2.5</text></g>
<g><rect class="nj-heat-3" x="248" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="286" y="496" text-anchor="middle">2.5 to 5</text></g>
<g><rect class="nj-heat-4" x="328" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="366" y="496" text-anchor="middle">5 and more</text></g>
<rect class="nj-heat-na" x="420" y="482" width="40" height="20" rx="3"/>
<text class="nj-charts-tick" x="440" y="496">n/a</text>
<text class="nj-charts-tick nj-charts-tick--l" x="468" y="496">no A&#8203;PI for it</text>
</svg>

</div>

<p class="nj-caption" markdown>Time per library and use case on an Apple M1 Max: each library's fastest fully validating
way, as the geometric mean over `twitter.json`, `citm_catalog.json`, `canada.json` and `jeopardy.json`, so that every
file counts equally, divided by the fastest library's mean, which therefore shows 1.00. Less is better. Where a way that
checks or does less is at least 3% faster, it is shown in the right half of the cell: "U" trusts UTF-8, "P" reads
lazily, only removes whitespace or, in one Glaze cell on x86-64, doesn't check what follows the value, and "N" copies
number text instead of formatting it. "n/a" means the library has no API for the use case. Hover over or tap a cell for
the times per file and the way; the tables are in [Appendix E](#e-comparison-with-other-libraries). sonic-cpp's README
lists only x86-64 Linux; we show it on the Mac anyway.</p>

### Results on the Mac

On the Apple M1 Max, among the ways that reject all four broken inputs, `json_document` has the lowest mean on the four
files in all six use cases, and yyjson is the next library in every column; in *validate*, `json::accept()` comes in
between (1.38× against yyjson's 1.41×). That includes editing, where the editable document is
faster than yyjson's mutable document: the speed doesn't depend on being read-only.

Some caveats belong next to that:

- **The lead is not the same on every file.** On `twitter.json`, yyjson is within 4–7% in *validate*, *sum*, and
  *select*. Most of the lead comes from `citm_catalog.json`, the floats of `canada.json` (next point) and the size of
  `jeopardy.json`.
- **Floats are converted only when read.** That helps `json_document` in *validate* and *select* on `canada.json`, where
  most others convert 111,080 floats nobody looks at. Libraries that can skip the conversion use that mode there, but
  only Boost.JSON gains much: it validates `canada.json` in 47% of the time. *sum* reads every number, so it is the fair
  comparison for floats; there, `json_document` is still slightly ahead of yyjson.
- **Checking less pays in *select*.** If the input needn't be checked fully, simdjson's On-Demand API and Glaze reading
  into structs select in 0.76× and 0.81× `json_document`'s time (Glaze is faster only on `citm_catalog.json` and
  `canada.json`), and in 0.55–0.61× on x86-64: the right halves of the *select* column.
- **Indentation.** Two of the four files are indented, which theme
  <a class="nj-theme" href="#theme-2" title="theme 2">2</a> helps. On minified copies of `twitter.json` and
  `citm_catalog.json`, yyjson comes closer in *sum* (1.11 → 1.01) and a little in *validate* (1.27 → 1.24), and
  `json_document` stays first.
- **Number text can be copied.** With [`number_format::source`](../../api/basic_json_view/number_format.md),
  `json_document` writes each number by copying its text instead of formatting it, and yyjson and RapidJSON can read
  numbers as text and write them back unchanged. The output keeps the source's spelling of each number, which is all a
  minifier needs. It makes writing `canada.json` with `json_document` 4.1× as fast and minifying it 1.9× as fast; the
  "N" halves of *edit*, *minify*, and *write* show it.
- **Small documents.** On a 2.5 KB message, the fastest libraries take about a microsecond on the Mac and 1.1–2 on
  x86-64. yyjson validates and sums it as fast as `json_document` on the Mac, and with GCC on x86-64, simdjson and
  yyjson sum it as fast.

### Reading into structs

A view can be converted into your own types with the same [`from_json()`](../../features/arbitrary_types.md) as `json`,
including the ones the [`NLOHMANN_DEFINE_TYPE_*`](../../api/macros/nlohmann_define_type_non_intrusive.md) macros
generate. That is as fast as picking the fields by hand from the view; only for the many small records of
`jeopardy.json` does it take 22% longer. On the Mac, Glaze, serde_json, and Boost.JSON's `parse_into`, reading into the
same structs and checking everything, take 1.7×, 2.3×, and 3.1× as long (geometric mean over the four files). On a
`json` value, reading into the structs takes about as long as `json::parse()` alone.

### nlohmann/json without `json_document`

And nlohmann/json without `json_document`? `json` builds a tree of separate allocations, and it shows: for *select*,
*edit*, and *minify* it takes several times as long as `json_document`, like Boost.JSON and RapidJSON. Where no tree is
needed, the fused parser ([One loop instead of two](#one-loop-instead-of-two)) puts it among the fastest:
[`json::accept()`](../../api/basic_json/accept.md) validates the four files in 1.38× `json_document`'s time on the Mac,
ahead of every other library, and a SAX handler sums them in 1.34×, behind only yyjson and simdjson. Boost.JSON takes
1.8× and 1.5× as long as `json` there, and 1.2–1.4× and 1.1–1.3× on x86-64. `dump()` writes faster than Boost.JSON,
RapidJSON and serde_json, and about as fast as Glaze.

Much of Boost.JSON's lead in building a tree comes from its allocator: here it builds the tree in a
`monotonic_resource`, an arena that is freed in one go, which saves it 27–40%. With its default allocator, which
allocates every string, array, and object on its own as `json` does, `boost::json::parse()` with precise numbers takes
13–17% longer than `json::parse()` on `twitter.json`, 19–20% longer on `citm_catalog.json`, and 2% less time on
`canada.json` (on the Mac, freeing the tree included).

### Results on x86-64

On x86-64, the same programs ran on a virtual server with Ubuntu 26.04 whose CPU presents itself as Haswell, pinned to
one core. We built them with `-march=haswell` and three compilers: the newest GCC, 16.2 (the figure below), GCC 13.4,
and Clang 23 (both in [Appendix E](#e-comparison-with-other-libraries)). The compiler matters less than one might think.
On the Mac, GCC 16 and Clang 23 put the same library first in every column as Apple clang, and on x86-64, the three
compilers disagree only about *sum*.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog nj-charts--heat" viewBox="0 0 784 510" role="img" aria-labelledby="nj-blog-uc-x86-gcc nj-blog-uc-x86-gcc-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-uc-x86-gcc">Use cases: time of each library relative to the fastest, x86-64 with G&#8203;CC 16.2</title>
<desc id="nj-blog-uc-x86-gcc-d">Table of relative times, libraries by use case. nlohmann/json json_document validate: 1.00; nlohmann/json json_document sum: 1.10; nlohmann/json json_document select: 1.00; nlohmann/json json_document edit: 1.00 (0.78 doing less, N); nlohmann/json json_document minify: 1.00 (0.78 doing less, N); nlohmann/json json_document write: 1.00 (0.64 doing less, N); yyjson validate: 2.23; yyjson sum: 1.31; yyjson select: 1.37; yyjson edit: 1.43; yyjson minify: 1.24 (0.99 doing less, N); yyjson write: 1.08; sonic-cpp validate: no fully validating way (2.32 doing less, U); sonic-cpp sum: no fully validating way (1.26 doing less, U); sonic-cpp select: no fully validating way (1.43 doing less, U); sonic-cpp edit: no fully validating way (1.18 doing less, U); sonic-cpp minify: no fully validating way (1.33 doing less, U); sonic-cpp write: 1.49; simdjson validate: 2.08; simdjson sum: 1.00; simdjson select: 1.29 (0.55 doing less, P); simdjson edit: n/a; simdjson minify: 1.49 (0.17 doing less, P); simdjson write: 2.09; sonic-rs (Rust) validate: 1.98; sonic-rs (Rust) sum: 1.14; sonic-rs (Rust) select: 1.36; sonic-rs (Rust) edit: 1.87; sonic-rs (Rust) minify: 1.68; sonic-rs (Rust) write: 2.05; Boost.J&#8203;SON validate: 1.98; Boost.J&#8203;SON sum: 1.29; Boost.J&#8203;SON select: 2.21; Boost.J&#8203;SON edit: 2.33; Boost.J&#8203;SON minify: 2.54; Boost.J&#8203;SON write: 2.33; nlohmann/json json validate: 1.69; nlohmann/json json sum: 1.17; nlohmann/json json select: 6.20; nlohmann/json json edit: 3.42; nlohmann/json json minify: 4.07; nlohmann/json json write: 1.84; simd-json (Rust) validate: 3.71; simd-json (Rust) sum: 1.93; simd-json (Rust) select: 2.59; simd-json (Rust) edit: 2.83; simd-json (Rust) minify: 3.30; simd-json (Rust) write: 2.34; serde_json (Rust) validate: 2.46 (2.19 doing less, U); serde_json (Rust) sum: 2.38; serde_json (Rust) select: 1.74; serde_json (Rust) edit: 4.45; serde_json (Rust) minify: 4.80; serde_json (Rust) write: 2.27; RapidJSON validate: 3.86 (3.48 doing less, U); RapidJSON sum: 2.35 (2.15 doing less, U); RapidJSON select: 3.17 (3.02 doing less, U); RapidJSON edit: 2.49 (2.40 doing less, U); RapidJSON minify: 2.58 (2.36 doing less, U N); RapidJSON write: 2.94; Glaze validate: 2.87; Glaze sum: 4.05; Glaze select: 1.71 (0.59 doing less, P); Glaze edit: 4.48; Glaze minify: 4.56 (0.75 doing less, P); Glaze write: 1.96.</desc>
<text class="nj-charts-tick" x="270" y="34">validate</text>
<text class="nj-charts-tick" x="362" y="34">sum</text>
<text class="nj-charts-tick" x="454" y="34">select</text>
<text class="nj-charts-tick" x="546" y="34">edit</text>
<text class="nj-charts-tick" x="638" y="34">minify</text>
<text class="nj-charts-tick" x="730" y="34">write</text>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="66" text-anchor="end">nlohmann/json json_document</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · validate&#10;1.00× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 254 µs&#10;citm_catalog.json: 515 µs&#10;canada.json: 892 µs&#10;jeopardy.json: 33,006 µs">
<rect class="nj-heat-0" x="225" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · sum&#10;1.10× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 384 µs&#10;citm_catalog.json: 1,066 µs&#10;canada.json: 3,526 µs&#10;jeopardy.json: 88,527 µs">
<rect class="nj-heat-0" x="317" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="66" text-anchor="middle">1.10</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · select&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 325 µs&#10;citm_catalog.json: 863 µs&#10;canada.json: 1,302 µs&#10;jeopardy.json: 87,940 µs">
<rect class="nj-heat-0" x="409" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit&#10;1.00× the time of the fastest library (fully validating)&#10;way: editable&#10;twitter.json: 538 µs&#10;citm_catalog.json: 1,214 µs&#10;canada.json: 5,640 µs&#10;jeopardy.json: 193,024 µs">
<rect class="nj-heat-0" x="501" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit, checking less&#10;0.78× the time of the fastest fully validating library&#10;twitter.json: 533 µs · editable (source numbers) (validates fully)&#10;citm_catalog.json: 1,214 µs · editable (validates fully)&#10;canada.json: 2,140 µs · editable (source numbers) (validates fully)&#10;jeopardy.json: 193,024 µs · editable (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="547" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="60" text-anchor="middle">0.78</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 478 µs&#10;citm_catalog.json: 1,152 µs&#10;canada.json: 5,209 µs&#10;jeopardy.json: 152,631 µs">
<rect class="nj-heat-0" x="593" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify, checking less&#10;0.78× the time of the fastest fully validating library&#10;way: parse + dump (source numbers)&#10;twitter.json: 467 µs (validates fully)&#10;citm_catalog.json: 1,118 µs (validates fully)&#10;canada.json: 2,150 µs (validates fully)&#10;jeopardy.json: 145,664 µs (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="639" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="60" text-anchor="middle">0.78</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write&#10;1.00× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 154 µs&#10;citm_catalog.json: 251 µs&#10;canada.json: 3,946 µs&#10;jeopardy.json: 64,776 µs">
<rect class="nj-heat-0" x="685" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="707.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write, checking less&#10;0.64× the time of the fastest fully validating library&#10;way: dump (source numbers)&#10;twitter.json: 139 µs (validates fully)&#10;citm_catalog.json: 229 µs (validates fully)&#10;canada.json: 831 µs (validates fully)&#10;jeopardy.json: 62,866 µs (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="731" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="752.5" y="60" text-anchor="middle">0.64</text>
<text class="nj-charts-cell nj-charts-cell--small" x="752.5" y="73" text-anchor="middle">N</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="102" text-anchor="end">yyjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · validate&#10;2.23× the time of the fastest library (fully validating)&#10;twitter.json: 393 µs · read&#10;citm_catalog.json: 930 µs · read (raw numbers)&#10;canada.json: 2,140 µs · read (raw numbers)&#10;jeopardy.json: 122,230 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="225" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="102" text-anchor="middle">2.23</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · sum&#10;1.31× the time of the fastest library (fully validating)&#10;way: read&#10;twitter.json: 445 µs&#10;citm_catalog.json: 1,093 µs&#10;canada.json: 3,948 µs&#10;jeopardy.json: 133,860 µs">
<rect class="nj-heat-1" x="317" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="102" text-anchor="middle">1.31</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · select&#10;1.37× the time of the fastest library (fully validating)&#10;twitter.json: 402 µs · read (raw numbers)&#10;citm_catalog.json: 954 µs · read&#10;canada.json: 2,127 µs · read (raw numbers)&#10;jeopardy.json: 140,491 µs · read">
<rect class="nj-heat-1" x="409" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="102" text-anchor="middle">1.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · edit&#10;1.43× the time of the fastest library (fully validating)&#10;twitter.json: 786 µs · mut copy&#10;citm_catalog.json: 1,642 µs · insitu (copy) + mut copy&#10;canada.json: 7,599 µs · insitu (copy) + mut copy&#10;jeopardy.json: 303,303 µs · mut copy&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="501" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="102" text-anchor="middle">1.43</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify&#10;1.24× the time of the fastest library (fully validating)&#10;twitter.json: 610 µs · read + write&#10;citm_catalog.json: 1,277 µs · read + write&#10;canada.json: 6,630 µs · read + write&#10;jeopardy.json: 199,086 µs · insitu (copy) + write&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="593" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="102" text-anchor="middle">1.24</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify, checking less&#10;0.99× the time of the fastest fully validating library&#10;twitter.json: 609 µs · read (raw numbers) + write (validates fully)&#10;citm_catalog.json: 1,221 µs · read (raw numbers) + write (validates fully)&#10;canada.json: 2,860 µs · read (raw numbers) + write (validates fully)&#10;jeopardy.json: 199,086 µs · insitu (copy) + write (validates fully)&#10;copies each number&#x27;s text instead of formatting it (YYJSON_READ_NUMBER_AS_RAW)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-0" x="639" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="96" text-anchor="middle">0.99</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="109" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · write&#10;1.08× the time of the fastest library (fully validating)&#10;way: write&#10;twitter.json: 185 µs&#10;citm_catalog.json: 318 µs&#10;canada.json: 3,330 µs&#10;jeopardy.json: 67,531 µs">
<rect class="nj-heat-0" x="685" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="102" text-anchor="middle">1.08</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="138" text-anchor="end">sonic-cpp</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · validate, checking less&#10;2.32× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 404 µs&#10;citm_catalog.json: 923 µs&#10;canada.json: 3,216 µs&#10;jeopardy.json: 93,142 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="225" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="132" text-anchor="middle">2.32</text>
<text class="nj-charts-cell nj-charts-cell--small" x="270" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · sum, checking less&#10;1.26× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 458 µs&#10;citm_catalog.json: 1,120 µs&#10;canada.json: 3,887 µs&#10;jeopardy.json: 107,494 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="317" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="132" text-anchor="middle">1.26</text>
<text class="nj-charts-cell nj-charts-cell--small" x="362" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · select, checking less&#10;1.43× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 408 µs&#10;citm_catalog.json: 942 µs&#10;canada.json: 3,166 µs&#10;jeopardy.json: 110,763 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="409" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="132" text-anchor="middle">1.43</text>
<text class="nj-charts-cell nj-charts-cell--small" x="454" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · edit, checking less&#10;1.18× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 620 µs&#10;citm_catalog.json: 1,426 µs&#10;canada.json: 8,466 µs&#10;jeopardy.json: 181,035 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="501" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="132" text-anchor="middle">1.18</text>
<text class="nj-charts-cell nj-charts-cell--small" x="546" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · minify, checking less&#10;1.33× the time of the fastest fully validating library&#10;way: Document + Serialize&#10;twitter.json: 636 µs&#10;citm_catalog.json: 1,498 µs&#10;canada.json: 8,354 µs&#10;jeopardy.json: 173,180 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="593" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="132" text-anchor="middle">1.33</text>
<text class="nj-charts-cell nj-charts-cell--small" x="638" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · write&#10;1.49× the time of the fastest library (fully validating)&#10;way: Serialize&#10;twitter.json: 258 µs&#10;citm_catalog.json: 508 µs&#10;canada.json: 5,077 µs&#10;jeopardy.json: 72,262 µs">
<rect class="nj-heat-1" x="685" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="138" text-anchor="middle">1.49</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="174" text-anchor="end">simdjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · validate&#10;2.08× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 297 µs&#10;citm_catalog.json: 687 µs&#10;canada.json: 3,165 µs&#10;jeopardy.json: 111,631 µs">
<rect class="nj-heat-2" x="225" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="174" text-anchor="middle">2.08</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · sum&#10;1.00× the time of the fastest library (fully validating)&#10;way: On-Demand&#10;twitter.json: 344 µs&#10;citm_catalog.json: 809 µs&#10;canada.json: 3,405 µs&#10;jeopardy.json: 90,960 µs">
<rect class="nj-heat-0" x="317" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="174" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select&#10;1.29× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 311 µs&#10;citm_catalog.json: 698 µs&#10;canada.json: 3,141 µs&#10;jeopardy.json: 130,228 µs">
<rect class="nj-heat-1" x="409" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="174" text-anchor="middle">1.29</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select, checking less&#10;0.55× the time of the fastest fully validating library&#10;twitter.json: 178 µs · On-Demand&#10;citm_catalog.json: 494 µs · On-Demand (key selectors)&#10;canada.json: 674 µs · On-Demand&#10;jeopardy.json: 48,492 µs · On-Demand&#10;reads lazily: On-Demand reads only what you ask for and steps over the rest by matching brackets">
<rect class="nj-heat-0" x="455" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="168" text-anchor="middle">0.55</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · edit&#10;simdjson&#x27;s documents are read-only: it has no A&#8203;PI to change a value and write the result">
<rect class="nj-heat-na" x="501" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-tick" x="546" y="174">n/a</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify&#10;1.49× the time of the fastest library (fully validating)&#10;way: D&#8203;OM + to_string&#10;twitter.json: 666 µs&#10;citm_catalog.json: 1,354 µs&#10;canada.json: 8,606 µs&#10;jeopardy.json: 280,739 µs">
<rect class="nj-heat-1" x="593" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="174" text-anchor="middle">1.49</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify, checking less&#10;0.17× the time of the fastest fully validating library&#10;way: minify&#10;twitter.json: 93.3 µs&#10;citm_catalog.json: 279 µs&#10;canada.json: 314 µs&#10;jeopardy.json: 46,006 µs&#10;simdjson::minify() only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="168" text-anchor="middle">0.17</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · write&#10;2.09× the time of the fastest library (fully validating)&#10;way: to_string&#10;twitter.json: 346 µs&#10;citm_catalog.json: 610 µs&#10;canada.json: 5,580 µs&#10;jeopardy.json: 158,670 µs">
<rect class="nj-heat-2" x="685" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="174" text-anchor="middle">2.09</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="210" text-anchor="end">sonic-rs (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · validate&#10;1.98× the time of the fastest library (fully validating)&#10;way: IgnoredAny&#10;twitter.json: 501 µs&#10;citm_catalog.json: 970 µs&#10;canada.json: 2,249 µs&#10;jeopardy.json: 54,369 µs">
<rect class="nj-heat-2" x="225" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="210" text-anchor="middle">1.98</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · sum&#10;1.14× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 501 µs&#10;citm_catalog.json: 1,123 µs&#10;canada.json: 4,397 µs&#10;jeopardy.json: 59,583 µs">
<rect class="nj-heat-0" x="317" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="210" text-anchor="middle">1.14</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · select&#10;1.36× the time of the fastest library (fully validating)&#10;way: structs&#10;twitter.json: 504 µs&#10;citm_catalog.json: 1,033 µs&#10;canada.json: 2,328 µs&#10;jeopardy.json: 90,486 µs">
<rect class="nj-heat-1" x="409" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="210" text-anchor="middle">1.36</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · edit&#10;1.87× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,197 µs&#10;citm_catalog.json: 2,389 µs&#10;canada.json: 7,744 µs&#10;jeopardy.json: 390,952 µs">
<rect class="nj-heat-2" x="501" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="210" text-anchor="middle">1.87</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · minify&#10;1.68× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,000 µs&#10;citm_catalog.json: 2,097 µs&#10;canada.json: 7,795 µs&#10;jeopardy.json: 215,280 µs">
<rect class="nj-heat-2" x="593" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="210" text-anchor="middle">1.68</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · write&#10;2.05× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 434 µs&#10;citm_catalog.json: 927 µs&#10;canada.json: 3,987 µs&#10;jeopardy.json: 109,176 µs">
<rect class="nj-heat-2" x="685" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="210" text-anchor="middle">2.05</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="246" text-anchor="end">Boost.J&#8203;SON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · validate&#10;1.98× the time of the fastest library (fully validating)&#10;way: S&#8203;AX (numbers: none)&#10;twitter.json: 683 µs&#10;citm_catalog.json: 913 µs&#10;canada.json: 1,642 µs&#10;jeopardy.json: 57,932 µs">
<rect class="nj-heat-2" x="225" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="246" text-anchor="middle">1.98</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · sum&#10;1.29× the time of the fastest library (fully validating)&#10;way: S&#8203;AX&#10;twitter.json: 690 µs&#10;citm_catalog.json: 956 µs&#10;canada.json: 5,762 µs&#10;jeopardy.json: 62,051 µs">
<rect class="nj-heat-1" x="317" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="246" text-anchor="middle">1.29</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · select&#10;2.21× the time of the fastest library (fully validating)&#10;twitter.json: 883 µs · parse_into structs&#10;citm_catalog.json: 1,286 µs · parse_into structs&#10;canada.json: 6,690 µs · parse&#10;jeopardy.json: 101,286 µs · parse_into structs">
<rect class="nj-heat-2" x="409" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="246" text-anchor="middle">2.21</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · edit&#10;2.33× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 1,859 µs&#10;citm_catalog.json: 2,513 µs&#10;canada.json: 12,765 µs&#10;jeopardy.json: 348,703 µs">
<rect class="nj-heat-2" x="501" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="246" text-anchor="middle">2.33</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · minify&#10;2.54× the time of the fastest library (fully validating)&#10;way: parse + serialize&#10;twitter.json: 1,783 µs&#10;citm_catalog.json: 2,498 µs&#10;canada.json: 12,367 µs&#10;jeopardy.json: 329,300 µs">
<rect class="nj-heat-3" x="593" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="246" text-anchor="middle">2.54</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · write&#10;2.33× the time of the fastest library (fully validating)&#10;way: serialize&#10;twitter.json: 451 µs&#10;citm_catalog.json: 832 µs&#10;canada.json: 5,570 µs&#10;jeopardy.json: 138,780 µs">
<rect class="nj-heat-2" x="685" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="246" text-anchor="middle">2.33</text>
</g>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="282" text-anchor="end">nlohmann/json json</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · validate&#10;1.69× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 370 µs&#10;citm_catalog.json: 883 µs&#10;canada.json: 2,441 µs&#10;jeopardy.json: 39,142 µs">
<rect class="nj-heat-2" x="225" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="282" text-anchor="middle">1.69</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · sum&#10;1.17× the time of the fastest library (fully validating)&#10;way: sax&#10;twitter.json: 533 µs&#10;citm_catalog.json: 1,113 µs&#10;canada.json: 4,134 µs&#10;jeopardy.json: 66,403 µs">
<rect class="nj-heat-1" x="317" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="282" text-anchor="middle">1.17</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · select&#10;6.20× the time of the fastest library (fully validating)&#10;twitter.json: 2,984 µs · parse&#10;citm_catalog.json: 4,548 µs · parse&#10;canada.json: 9,124 µs · structs (from_json)&#10;jeopardy.json: 383,108 µs · parse">
<rect class="nj-heat-4" x="409" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="282" text-anchor="middle">6.20</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · edit&#10;3.42× the time of the fastest library (fully validating)&#10;twitter.json: 2,535 µs · ordered_json&#10;citm_catalog.json: 4,484 µs · ordered_json&#10;canada.json: 13,526 µs · parse&#10;jeopardy.json: 635,912 µs · ordered_json">
<rect class="nj-heat-3" x="501" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="282" text-anchor="middle">3.42</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · minify&#10;4.07× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 3,369 µs&#10;citm_catalog.json: 5,399 µs&#10;canada.json: 13,402 µs&#10;jeopardy.json: 493,302 µs">
<rect class="nj-heat-3" x="593" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="282" text-anchor="middle">4.07</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · write&#10;1.84× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 413 µs&#10;citm_catalog.json: 611 µs&#10;canada.json: 3,905 µs&#10;jeopardy.json: 113,990 µs">
<rect class="nj-heat-2" x="685" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="282" text-anchor="middle">1.84</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="318" text-anchor="end">simd-json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · validate&#10;3.71× the time of the fastest library (fully validating)&#10;way: tape (copy)&#10;twitter.json: 567 µs&#10;citm_catalog.json: 1,430 µs&#10;canada.json: 4,359 µs&#10;jeopardy.json: 207,551 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="318" text-anchor="middle">3.71</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · sum&#10;1.93× the time of the fastest library (fully validating)&#10;way: visitor (copy)&#10;twitter.json: 681 µs&#10;citm_catalog.json: 1,650 µs&#10;canada.json: 5,083 µs&#10;jeopardy.json: 210,185 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="317" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="318" text-anchor="middle">1.93</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · select&#10;2.59× the time of the fastest library (fully validating)&#10;way: structs (copy)&#10;twitter.json: 679 µs&#10;citm_catalog.json: 1,731 µs&#10;canada.json: 5,144 µs&#10;jeopardy.json: 239,164 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="318" text-anchor="middle">2.59</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · edit&#10;2.83× the time of the fastest library (fully validating)&#10;twitter.json: 1,862 µs · borrowed (copy)&#10;citm_catalog.json: 4,194 µs · borrowed (copy)&#10;canada.json: 14,896 µs · owned (copy)&#10;jeopardy.json: 391,369 µs · borrowed (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="318" text-anchor="middle">2.83</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · minify&#10;3.30× the time of the fastest library (fully validating)&#10;way: borrowed (copy)&#10;twitter.json: 1,889 µs&#10;citm_catalog.json: 4,196 µs&#10;canada.json: 15,716 µs&#10;jeopardy.json: 414,377 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="593" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="318" text-anchor="middle">3.30</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · write&#10;2.34× the time of the fastest library (fully validating)&#10;way: borrowed&#10;twitter.json: 582 µs&#10;citm_catalog.json: 800 µs&#10;canada.json: 5,147 µs&#10;jeopardy.json: 122,623 µs">
<rect class="nj-heat-2" x="685" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="318" text-anchor="middle">2.34</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="354" text-anchor="end">serde_json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate&#10;2.46× the time of the fastest library (fully validating)&#10;way: from_utf8 + IgnoredAny&#10;twitter.json: 624 µs&#10;citm_catalog.json: 1,440 µs&#10;canada.json: 2,406 µs&#10;jeopardy.json: 64,720 µs">
<rect class="nj-heat-2" x="225" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="354" text-anchor="middle">2.46</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate, checking less&#10;2.19× the time of the fastest fully validating library&#10;way: IgnoredAny&#10;twitter.json: 484 µs&#10;citm_catalog.json: 1,370 µs&#10;canada.json: 2,314 µs&#10;jeopardy.json: 58,247 µs&#10;trusts U&#8203;TF-8 in the strings it skips (from_slice); strings it reads are checked">
<rect class="nj-heat-2" x="271" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="348" text-anchor="middle">2.19</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="361" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · sum&#10;2.38× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 1,311 µs&#10;citm_catalog.json: 2,288 µs&#10;canada.json: 7,127 µs&#10;jeopardy.json: 129,497 µs">
<rect class="nj-heat-2" x="317" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="354" text-anchor="middle">2.38</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · select&#10;1.74× the time of the fastest library (fully validating)&#10;way: from_utf8 + structs&#10;twitter.json: 701 µs&#10;citm_catalog.json: 1,532 µs&#10;canada.json: 2,529 µs&#10;jeopardy.json: 107,316 µs">
<rect class="nj-heat-2" x="409" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="354" text-anchor="middle">1.74</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · edit&#10;4.45× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,042 µs&#10;citm_catalog.json: 6,586 µs&#10;canada.json: 16,631 µs&#10;jeopardy.json: 632,766 µs">
<rect class="nj-heat-3" x="501" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="354" text-anchor="middle">4.45</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · minify&#10;4.80× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,012 µs&#10;citm_catalog.json: 6,583 µs&#10;canada.json: 17,306 µs&#10;jeopardy.json: 509,702 µs">
<rect class="nj-heat-3" x="593" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="354" text-anchor="middle">4.80</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · write&#10;2.27× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 550 µs&#10;citm_catalog.json: 887 µs&#10;canada.json: 4,005 µs&#10;jeopardy.json: 134,163 µs">
<rect class="nj-heat-2" x="685" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="354" text-anchor="middle">2.27</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="390" text-anchor="end">RapidJSON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate&#10;3.86× the time of the fastest library (fully validating)&#10;twitter.json: 1,215 µs · insitu (copy)&#10;citm_catalog.json: 1,550 µs · S&#8203;AX (string stream, default precision)&#10;canada.json: 3,625 µs · S&#8203;AX (string stream, default precision)&#10;jeopardy.json: 125,139 µs · S&#8203;AX (string stream, default precision)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="390" text-anchor="middle">3.86</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate, checking less&#10;3.48× the time of the fastest fully validating library&#10;twitter.json: 1,052 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,427 µs · S&#8203;AX (default precision) (no encoding check)&#10;canada.json: 3,625 µs · S&#8203;AX (string stream, default precision) (validates fully)&#10;jeopardy.json: 104,342 µs · S&#8203;AX (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="271" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="384" text-anchor="middle">3.48</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum&#10;2.35× the time of the fastest library (fully validating)&#10;twitter.json: 1,256 µs · insitu (copy)&#10;citm_catalog.json: 1,713 µs · S&#8203;AX (string stream)&#10;canada.json: 9,547 µs · S&#8203;AX (string stream)&#10;jeopardy.json: 127,564 µs · S&#8203;AX (string stream)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="317" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="390" text-anchor="middle">2.35</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum, checking less&#10;2.15× the time of the fastest fully validating library&#10;twitter.json: 1,099 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,635 µs · S&#8203;AX (string stream) (no encoding check)&#10;canada.json: 9,105 µs · S&#8203;AX (string stream) (no encoding check)&#10;jeopardy.json: 113,500 µs · S&#8203;AX (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="363" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="384" text-anchor="middle">2.15</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select&#10;3.17× the time of the fastest library (fully validating)&#10;twitter.json: 1,217 µs · insitu (copy)&#10;citm_catalog.json: 1,807 µs · insitu (copy)&#10;canada.json: 9,688 µs · Document (string stream)&#10;jeopardy.json: 152,275 µs · Document (string stream)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="390" text-anchor="middle">3.17</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select, checking less&#10;3.02× the time of the fastest fully validating library&#10;twitter.json: 1,056 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,767 µs · insitu (copy) (no encoding check)&#10;canada.json: 9,632 µs · Document (string stream) (no encoding check)&#10;jeopardy.json: 148,964 µs · Document (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="455" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="384" text-anchor="middle">3.02</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit&#10;2.49× the time of the fastest library (fully validating)&#10;twitter.json: 1,896 µs · insitu (copy)&#10;citm_catalog.json: 2,754 µs · insitu (copy)&#10;canada.json: 19,359 µs · Document (string stream)&#10;jeopardy.json: 269,071 µs · Document (string stream)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="501" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="390" text-anchor="middle">2.49</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit, checking less&#10;2.40× the time of the fastest fully validating library&#10;twitter.json: 1,749 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 2,730 µs · insitu (copy) (no encoding check)&#10;canada.json: 19,155 µs · Document (string stream) (no encoding check)&#10;jeopardy.json: 259,148 µs · Document (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="547" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="384" text-anchor="middle">2.40</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="397" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify&#10;2.58× the time of the fastest library (fully validating)&#10;way: S&#8203;AX to Writer (string stream)&#10;twitter.json: 1,851 µs&#10;citm_catalog.json: 2,429 µs&#10;canada.json: 18,810 µs&#10;jeopardy.json: 229,769 µs">
<rect class="nj-heat-3" x="593" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="390" text-anchor="middle">2.58</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify, checking less&#10;2.36× the time of the fastest fully validating library&#10;twitter.json: 1,710 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;citm_catalog.json: 2,429 µs · S&#8203;AX to Writer (string stream) (validates fully)&#10;canada.json: 14,205 µs · S&#8203;AX to Writer (raw numbers) (validates fully)&#10;jeopardy.json: 229,769 µs · S&#8203;AX to Writer (string stream) (validates fully)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;copies each number&#x27;s text instead of formatting it (kParseNumbersAsStringsFlag)">
<rect class="nj-heat-2" x="639" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="384" text-anchor="middle">2.36</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="397" text-anchor="middle">U N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · write&#10;2.94× the time of the fastest library (fully validating)&#10;way: Writer&#10;twitter.json: 638 µs&#10;citm_catalog.json: 984 µs&#10;canada.json: 8,886 µs&#10;jeopardy.json: 131,435 µs">
<rect class="nj-heat-3" x="685" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="390" text-anchor="middle">2.94</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="426" text-anchor="end">Glaze</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · validate&#10;2.87× the time of the fastest library (fully validating)&#10;way: validate_json&#10;twitter.json: 705 µs&#10;citm_catalog.json: 1,971 µs&#10;canada.json: 2,532 µs&#10;jeopardy.json: 74,805 µs">
<rect class="nj-heat-3" x="225" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="426" text-anchor="middle">2.87</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum&#10;4.05× the time of the fastest library (fully validating)&#10;way: generic (double, strict)&#10;twitter.json: 2,317 µs&#10;citm_catalog.json: 4,068 µs&#10;canada.json: 10,333 µs&#10;jeopardy.json: 237,723 µs">
<rect class="nj-heat-3" x="317" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="426" text-anchor="middle">4.05</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select&#10;1.71× the time of the fastest library (fully validating)&#10;way: structs (validate_skipped)&#10;twitter.json: 608 µs&#10;citm_catalog.json: 1,978 µs&#10;canada.json: 2,521 µs&#10;jeopardy.json: 90,807 µs">
<rect class="nj-heat-2" x="409" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="426" text-anchor="middle">1.71</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select, checking less&#10;0.59× the time of the fastest fully validating library&#10;way: structs&#10;twitter.json: 345 µs&#10;citm_catalog.json: 401 µs&#10;canada.json: 415 µs&#10;jeopardy.json: 67,456 µs&#10;reads into structs and steps over fields it doesn&#x27;t know without checking them (validate_skipped checks them too)">
<rect class="nj-heat-0" x="455" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="420" text-anchor="middle">0.59</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="433" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · edit&#10;4.48× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,364 µs&#10;citm_catalog.json: 6,036 µs&#10;canada.json: 21,592 µs&#10;jeopardy.json: 652,302 µs">
<rect class="nj-heat-3" x="501" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="426" text-anchor="middle">4.48</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify&#10;4.56× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,243 µs&#10;citm_catalog.json: 6,175 µs&#10;canada.json: 20,961 µs&#10;jeopardy.json: 451,368 µs">
<rect class="nj-heat-3" x="593" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="426" text-anchor="middle">4.56</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify, checking less&#10;0.75× the time of the fastest fully validating library&#10;way: minify_json&#10;twitter.json: 417 µs&#10;citm_catalog.json: 1,299 µs&#10;canada.json: 2,699 µs&#10;jeopardy.json: 93,794 µs&#10;minify_json only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="420" text-anchor="middle">0.75</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="433" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · write&#10;1.96× the time of the fastest library (fully validating)&#10;way: generic&#10;twitter.json: 377 µs&#10;citm_catalog.json: 730 µs&#10;canada.json: 4,050 µs&#10;jeopardy.json: 129,720 µs">
<rect class="nj-heat-2" x="685" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="426" text-anchor="middle">1.96</text>
</g>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="472">time relative to the fastest fully validating library, less is better</text>
<g><rect class="nj-heat-0" x="8" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="46" y="496" text-anchor="middle">below 1.15</text></g>
<g><rect class="nj-heat-1" x="88" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="126" y="496" text-anchor="middle">1.15 to 1.5</text></g>
<g><rect class="nj-heat-2" x="168" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="206" y="496" text-anchor="middle">1.5 to 2.5</text></g>
<g><rect class="nj-heat-3" x="248" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="286" y="496" text-anchor="middle">2.5 to 5</text></g>
<g><rect class="nj-heat-4" x="328" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="366" y="496" text-anchor="middle">5 and more</text></g>
<rect class="nj-heat-na" x="420" y="482" width="40" height="20" rx="3"/>
<text class="nj-charts-tick" x="440" y="496">n/a</text>
<text class="nj-charts-tick nj-charts-tick--l" x="468" y="496">no A&#8203;PI for it</text>
</svg>

</div>

<p class="nj-caption" markdown>The same comparison on the x86-64 server with GCC 16.2, with the same cells and halves as
the figure above. Less is better; hover over or tap a cell for the times and the way. The figures for GCC 13 and Clang
23 are in [Appendix E](#e-comparison-with-other-libraries).</p>

`json_document` has the lowest mean in five of the six columns with every compiler. The exception is *sum*, where
simdjson is ahead with GCC, and `json` with a SAX handler with GCC 13 and Clang 23 (with Clang by 5%, all of it on
`jeopardy.json`; below). This machine is noisy, though: between two runs, a library's time relative to
`json_document`'s moved by up to 7–8% (95th percentile; 2.4% on the Mac), so a lead of 5% is no result. In *validate*,
the next library takes 1.8–2.0× as long, or 1.6–1.7× if every library may reuse its parser, because validating no
longer builds an index (theme <a class="nj-theme" href="#theme-8" title="theme 8">8</a>). The only way in between is
`json::accept()` at 1.3–1.7×, which builds nothing either ([One loop instead of two](#one-loop-instead-of-two)).
Behind those means, `json_document` loses on single files:

- **One pass over every value, with GCC.** simdjson's On-Demand API sums all numbers of `twitter.json`,
  `citm_catalog.json`, and `canada.json` in 0.76–0.97× `json_document`'s time with GCC 16 (0.79–0.92× with GCC 13). With
  Clang, `json_document` is ahead there, except on `canada.json`, where yyjson, which converts the floats during the
  parse, is faster than converting them on access, and on `citm_catalog.json`, where `json`'s SAX handler and
  Boost.JSON's are 1–3% faster.
- **Fresh large documents.** For the 56 MB `jeopardy.json`, a fresh document needs a fresh 52 MB index, and on Linux the
  page faults of that much new memory are a large part of the time: copying the file into fresh memory alone takes about
  50% as long as `json_document`'s parse. Boost.JSON's SAX parser and sonic-rs, which build nothing, sum it in
  0.64–0.71× the time, and `json`'s SAX handler in 0.70–0.75×. Reusing the document cuts `json_document`'s time by
  41–43%, to 51 ms, less than sonic-rs's 60 ms. Validating needs no index: `json_document::accept()` takes 33–35 ms,
  `json::accept()` 39–40 ms, and no other library validates `jeopardy.json` faster, even reused (the next is simdjson's
  reused parser at 48–52 ms). On the Mac, a fresh document costs hardly more than a reused one.
- **Writing floats.** yyjson writes `canada.json` in 0.84–0.93× the time (and Glaze with GCC 13 and `json`'s `dump()`
  with GCC 16, which start from `double`s, in 0.98× and 0.99×), because `json_document` first converts most floats from
  their text. Writing the source text instead (`number_format::source`, the "N" half) avoids that.
- **simdjson's DOM.** It selects from `citm_catalog.json` 19% faster with GCC 16 and 7–13% faster with GCC 13 and Clang
  23, and from `twitter.json` 2–4% faster with GCC. Boost.JSON, Glaze, sonic-rs, sonic-cpp, and yyjson are ahead in a
  few more cells, by 1–10%: summing `citm_catalog.json` (Boost.JSON with GCC), and selecting from or writing
  `jeopardy.json`. Most of that is within the noise.

The full tables, with each library's variants, are in [Appendix E](#e-comparison-with-other-libraries).

### Files and checks we didn't choose { #files-and-checks-we-didnt-choose }

The four files are the ones 3.13.0 was tuned on, so we also ran *validate*, *sum*, *minify*, and *write* on the 19 other
files of simdjson's [`jsonexamples`](https://github.com/simdjson/simdjson-data/tree/master/jsonexamples). By geometric
mean, `json_document` stays the fastest in *validate*, *minify*, and *write* on every compiler, and in *sum* with Clang
and on the Mac; with GCC, simdjson sums in 0.87–0.88× its time. `json::accept()` validates them in 1.4–1.6× the time
of `json_document` on x86-64, close to simdjson (1.44–1.46×), the fastest other library. File by file, for *validate*:

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog" viewBox="0 0 620 482" role="img" aria-labelledby="nj-blog-heldout nj-blog-heldout-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-heldout">Validating 19 files 3.13.0 was not tuned on: json_document&#x27;s time relative to the fastest other library per file</title>
<desc id="nj-blog-heldout-d">Dot plot per file, less is better; below 1.0 json_document is the fastest fully validating library. mesh: Mac 0.72, x86-64 0.44 (serde_json (Rust)); semanticscholar-corpus: Mac 0.78, x86-64 0.63 (sonic-rs (Rust)); gsoc-2018: Mac 0.59, x86-64 0.64 (Boost.J&#8203;SON); marine_ik: Mac 0.62, x86-64 0.64 (Boost.J&#8203;SON); twitter_api_compact_response: Mac 0.91, x86-64 0.66 (yyjson); twitterescaped: Mac 0.94, x86-64 0.76 (simdjson); update-center: Mac 0.88, x86-64 0.77 (simdjson); github_events: Mac 0.78, x86-64 0.78 (simdjson); twitter_api_response: Mac 0.95, x86-64 0.81 (simdjson); twitter_timeline: Mac 0.99, x86-64 0.82 (yyjson); numbers: Mac 0.72, x86-64 0.82 (Boost.J&#8203;SON); random: Mac 0.82, x86-64 0.86 (simdjson); repeat: Mac 0.65, x86-64 0.89 (simdjson); apache_builds: Mac 1.08, x86-64 0.90 (simdjson); instruments: Mac 0.92, x86-64 0.91 (simdjson); google_maps_api_compact_response: Mac 0.87, x86-64 0.92 (yyjson); mesh.pretty: Mac 0.88, x86-64 0.93 (Boost.J&#8203;SON); tree-pretty: Mac 0.96, x86-64 0.94 (simdjson); google_maps_api_response: Mac 0.91, x86-64 1.00 (simdjson).</desc>
<line class="nj-charts-grid" x1="262" y1="50" x2="262" y2="438"/>
<text class="nj-charts-tick" x="262" y="454">0.4&#215;</text>
<line class="nj-charts-grid" x1="291.867" y1="50" x2="291.867" y2="438"/>
<text class="nj-charts-tick" x="291.867" y="454">0.5&#215;</text>
<line class="nj-charts-grid" x1="321.733" y1="50" x2="321.733" y2="438"/>
<text class="nj-charts-tick" x="321.733" y="454">0.6&#215;</text>
<line class="nj-charts-grid" x1="351.6" y1="50" x2="351.6" y2="438"/>
<text class="nj-charts-tick" x="351.6" y="454">0.7&#215;</text>
<line class="nj-charts-grid" x1="381.467" y1="50" x2="381.467" y2="438"/>
<text class="nj-charts-tick" x="381.467" y="454">0.8&#215;</text>
<line class="nj-charts-grid" x1="411.333" y1="50" x2="411.333" y2="438"/>
<text class="nj-charts-tick" x="411.333" y="454">0.9&#215;</text>
<line class="nj-charts-grid" x1="441.2" y1="50" x2="441.2" y2="438"/>
<text class="nj-charts-tick" x="441.2" y="454">1.0&#215;</text>
<line class="nj-charts-grid" x1="471.067" y1="50" x2="471.067" y2="438"/>
<text class="nj-charts-tick" x="471.067" y="454">1.1&#215;</text>
<text class="nj-charts-tick" x="374" y="472">json&#95;document&#8217;s time / the fastest other library&#8217;s, less is better</text>
<circle class="nj-charts-json-dot" cx="13" cy="14" r="5"/><text class="nj-charts-leg" x="23" y="18.5">Apple M1 Max</text>
<circle class="nj-charts-ojson-dot" cx="134.2" cy="14" r="5"/><text class="nj-charts-leg" x="144.2" y="18.5">x86-64, G&#8203;CC 16.2</text>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="48">next on x86-64</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="68" text-anchor="end">mesh</text>
<circle class="nj-charts-json-dot" cx="357.0" cy="60.5" r="4.5"><title>mesh, Apple M1 Max: 0.72&#215; the time of Glaze</title></circle>
<circle class="nj-charts-ojson-dot" cx="273.8" cy="67.5" r="4.5"><title>mesh, x86-64, G&#8203;CC 16.2: 0.44&#215; the time of serde&#95;json (Rust)</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="68">serde&#95;json (Rust)</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="88" text-anchor="end">semanticscholar-corpus</text>
<circle class="nj-charts-json-dot" cx="376.0" cy="80.5" r="4.5"><title>semanticscholar-corpus, Apple M1 Max: 0.78&#215; the time of sonic-rs (Rust)</title></circle>
<circle class="nj-charts-ojson-dot" cx="331.5" cy="87.5" r="4.5"><title>semanticscholar-corpus, x86-64, G&#8203;CC 16.2: 0.63&#215; the time of sonic-rs (Rust)</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="88">sonic-rs (Rust)</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="108" text-anchor="end">gsoc-2018</text>
<circle class="nj-charts-json-dot" cx="318.5" cy="100.5" r="4.5"><title>gsoc-2018, Apple M1 Max: 0.59&#215; the time of sonic-rs (Rust)</title></circle>
<circle class="nj-charts-ojson-dot" cx="332.3" cy="107.5" r="4.5"><title>gsoc-2018, x86-64, G&#8203;CC 16.2: 0.64&#215; the time of Boost.J&#8203;SON</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="108">Boost.J&#8203;SON</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="128" text-anchor="end">marine&#95;ik</text>
<circle class="nj-charts-json-dot" cx="326.2" cy="120.5" r="4.5"><title>marine&#95;ik, Apple M1 Max: 0.62&#215; the time of Glaze</title></circle>
<circle class="nj-charts-ojson-dot" cx="333.7" cy="127.5" r="4.5"><title>marine&#95;ik, x86-64, G&#8203;CC 16.2: 0.64&#215; the time of Boost.J&#8203;SON</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="128">Boost.J&#8203;SON</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="148" text-anchor="end">twitter&#95;api&#95;compact&#95;response</text>
<circle class="nj-charts-json-dot" cx="414.0" cy="140.5" r="4.5"><title>twitter&#95;api&#95;compact&#95;response, Apple M1 Max: 0.91&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="340.0" cy="147.5" r="4.5"><title>twitter&#95;api&#95;compact&#95;response, x86-64, G&#8203;CC 16.2: 0.66&#215; the time of yyjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="148">yyjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="168" text-anchor="end">twitterescaped</text>
<circle class="nj-charts-json-dot" cx="423.0" cy="160.5" r="4.5"><title>twitterescaped, Apple M1 Max: 0.94&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="368.5" cy="167.5" r="4.5"><title>twitterescaped, x86-64, G&#8203;CC 16.2: 0.76&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="168">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="188" text-anchor="end">update-center</text>
<circle class="nj-charts-json-dot" cx="404.3" cy="180.5" r="4.5"><title>update-center, Apple M1 Max: 0.88&#215; the time of sonic-rs (Rust)</title></circle>
<circle class="nj-charts-ojson-dot" cx="372.0" cy="187.5" r="4.5"><title>update-center, x86-64, G&#8203;CC 16.2: 0.77&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="188">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="208" text-anchor="end">github&#95;events</text>
<circle class="nj-charts-json-dot" cx="375.6" cy="200.5" r="4.5"><title>github&#95;events, Apple M1 Max: 0.78&#215; the time of simdjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="375.2" cy="207.5" r="4.5"><title>github&#95;events, x86-64, G&#8203;CC 16.2: 0.78&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="208">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="228" text-anchor="end">twitter&#95;api&#95;response</text>
<circle class="nj-charts-json-dot" cx="427.3" cy="220.5" r="4.5"><title>twitter&#95;api&#95;response, Apple M1 Max: 0.95&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="384.1" cy="227.5" r="4.5"><title>twitter&#95;api&#95;response, x86-64, G&#8203;CC 16.2: 0.81&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="228">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="248" text-anchor="end">twitter&#95;timeline</text>
<circle class="nj-charts-json-dot" cx="437.3" cy="240.5" r="4.5"><title>twitter&#95;timeline, Apple M1 Max: 0.99&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="386.2" cy="247.5" r="4.5"><title>twitter&#95;timeline, x86-64, G&#8203;CC 16.2: 0.82&#215; the time of yyjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="248">yyjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="268" text-anchor="end">numbers</text>
<circle class="nj-charts-json-dot" cx="358.0" cy="260.5" r="4.5"><title>numbers, Apple M1 Max: 0.72&#215; the time of Glaze</title></circle>
<circle class="nj-charts-ojson-dot" cx="386.3" cy="267.5" r="4.5"><title>numbers, x86-64, G&#8203;CC 16.2: 0.82&#215; the time of Boost.J&#8203;SON</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="268">Boost.J&#8203;SON</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="288" text-anchor="end">random</text>
<circle class="nj-charts-json-dot" cx="388.2" cy="280.5" r="4.5"><title>random, Apple M1 Max: 0.82&#215; the time of simdjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="400.0" cy="287.5" r="4.5"><title>random, x86-64, G&#8203;CC 16.2: 0.86&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="288">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="308" text-anchor="end">repeat</text>
<circle class="nj-charts-json-dot" cx="336.7" cy="300.5" r="4.5"><title>repeat, Apple M1 Max: 0.65&#215; the time of simdjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="409.2" cy="307.5" r="4.5"><title>repeat, x86-64, G&#8203;CC 16.2: 0.89&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="308">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="328" text-anchor="end">apache&#95;builds</text>
<circle class="nj-charts-json-dot" cx="465.2" cy="320.5" r="4.5"><title>apache&#95;builds, Apple M1 Max: 1.08&#215; the time of simdjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="412.0" cy="327.5" r="4.5"><title>apache&#95;builds, x86-64, G&#8203;CC 16.2: 0.90&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="328">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="348" text-anchor="end">instruments</text>
<circle class="nj-charts-json-dot" cx="417.1" cy="340.5" r="4.5"><title>instruments, Apple M1 Max: 0.92&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="415.6" cy="347.5" r="4.5"><title>instruments, x86-64, G&#8203;CC 16.2: 0.91&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="348">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="368" text-anchor="end">google&#95;maps&#95;api&#95;compact&#95;response</text>
<circle class="nj-charts-json-dot" cx="403.3" cy="360.5" r="4.5"><title>google&#95;maps&#95;api&#95;compact&#95;response, Apple M1 Max: 0.87&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="416.8" cy="367.5" r="4.5"><title>google&#95;maps&#95;api&#95;compact&#95;response, x86-64, G&#8203;CC 16.2: 0.92&#215; the time of yyjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="368">yyjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="388" text-anchor="end">mesh.pretty</text>
<circle class="nj-charts-json-dot" cx="405.5" cy="380.5" r="4.5"><title>mesh.pretty, Apple M1 Max: 0.88&#215; the time of Glaze</title></circle>
<circle class="nj-charts-ojson-dot" cx="419.6" cy="387.5" r="4.5"><title>mesh.pretty, x86-64, G&#8203;CC 16.2: 0.93&#215; the time of Boost.J&#8203;SON</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="388">Boost.J&#8203;SON</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="408" text-anchor="end">tree-pretty</text>
<circle class="nj-charts-json-dot" cx="427.9" cy="400.5" r="4.5"><title>tree-pretty, Apple M1 Max: 0.96&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="424.3" cy="407.5" r="4.5"><title>tree-pretty, x86-64, G&#8203;CC 16.2: 0.94&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="408">simdjson</text>
<text class="nj-charts-rowlabel nj-charts-code" x="252" y="428" text-anchor="end">google&#95;maps&#95;api&#95;response</text>
<circle class="nj-charts-json-dot" cx="415.8" cy="420.5" r="4.5"><title>google&#95;maps&#95;api&#95;response, Apple M1 Max: 0.91&#215; the time of yyjson</title></circle>
<circle class="nj-charts-ojson-dot" cx="441.2" cy="427.5" r="4.5"><title>google&#95;maps&#95;api&#95;response, x86-64, G&#8203;CC 16.2: 1.00&#215; the time of simdjson</title></circle>
<text class="nj-charts-tick nj-charts-tick--l" x="500" y="428">simdjson</text>
<line class="nj-charts-ref" x1="441.2" y1="50" x2="441.2" y2="438"/>
<text class="nj-charts-tick" x="441.2" y="44">as fast as the next</text>
</svg>

</div>

<p class="nj-caption" markdown>*validate* on the 19 files: `json_document`'s fastest fully validating way against the
fastest other library's, per file; below 1.0× it is the fastest. Less is better. The right column names the next library
on x86-64 (GCC 16.2).</p>

`json_document` validates 18 of the 19 files fastest with GCC 16, Clang 23, and on the Mac: simdjson ties on
`google_maps_api_response` with GCC 16, Boost.JSON on `mesh.pretty` with Clang 23, and simdjson validates
`apache_builds` 7% faster on the Mac. With GCC 13 it is 17: simdjson validates `google_maps_api_response` 6% faster,
and Boost.JSON `mesh.pretty` 10% faster (1% in the first of our two runs on November 7). Before validating
without an index (theme <a class="nj-theme" href="#theme-8" title="theme 8">8</a>) and skipping fraction digits 16 bytes
at a time (theme <a class="nj-theme" href="#theme-2" title="theme 2">2</a>), Boost.JSON validated the number-heavy files
up to 1.5× as fast on x86-64.

The four probes are broken inputs that tell full validation from less ([Appendix E](#e-comparison-with-other-libraries)
lists them). As a further check, every *validate* way also ran the 318 files of
[JSONTestSuite](https://github.com/nst/JSONTestSuite). [Appendix E](#e-comparison-with-other-libraries) lists the
exceptions, one of them ours. The suite also found that Glaze's generic reader accepts garbage after the value by
default, so the figures use its strict option.

We did not measure memory use, a CPU with AVX-512, MSVC, writing from structs, or streaming input.

## What didn't work

The pull requests record the ideas that measured worse, which is as useful as the ones that made it:

| idea | result |
| --- | --- |
| make every walk iterative | up to 20% slower on ordinary documents |
| move the key out of the lexer's reused buffer | 11.9% slower (later a win, see theme <a class="nj-theme" href="#theme-4" title="theme 4">4</a>) |
| inline `scan_literal()` | Clang's dispatch grew from 233 to 278 instructions and got slower |
| short-string table for strings up to 64 bytes | lost against 32 |
| leave the serializer's buffers uninitialized | timings moved 18% apart in opposite directions on two similar workloads, so dropped; done later, when instruction counts showed 170 instructions saved per `dump()` |
| move the throws of the JSON Pointer lookups out of line too | no measurable gain, dropped; they stay inline |
| `json_document`: an "all ASCII" flag per string | `dump()` with `ensure_ascii` faster, but parsing 1–13% slower |
| `json_document`: convert floats while parsing | `canada.json` parse 36–90% slower |
| `json_document`: note a large object inline in the parse loop | `canada.json` 37% slower |
| `json_document`: vector-scan every string in `set()` | 14–16% slower on 16-byte strings |

<p class="nj-table-caption" markdown>Ideas that were measured and dropped. [Appendix H](#h-pull-requests-by-theme) links
the pull requests that tried them.</p>

## The price

None of this is free at compile time. `json.hpp` grew from 25,526 to 48,025 lines (`json_view.hpp` is a separate header
of 11,909 lines that you only pay for if you include it). To see what that means for a program, we compiled two small
ones with both versions:

- `count_numbers` reads `twitter.json` and adds up all of its numbers, like the *sum* use case in [How it
  compares](#six-use-cases);
- `server_config` reads a configuration file into a struct with `to_json()` and `from_json()`, changes it, and writes it
  back with `dump(2)`.

Each is one translation unit. We timed it with the 3.12.0 and the 3.13.0 header, and then with 3.13.0 as a precompiled
header and as a C++20 module, in a debug build (`-O0`) and an optimized one (`-O2`):

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog" viewBox="0 0 600 618" role="img" aria-labelledby="nj-blog-price nj-blog-price-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-price">Compile time of two programs with 3.13.0, alone, with a precompiled header and as a module, compared with 3.12.0</title>
<desc id="nj-blog-price-d">Horizontal bars of the change in compile time against 3.12.0, less is better. Apple clang 21, -O0 (debug), count_numbers, 3.13.0: +36%; Apple clang 21, -O0 (debug), count_numbers, 3.13.0, precompiled header: -23%; Apple clang 21, -O0 (debug), count_numbers, 3.13.0, module: -5%; Apple clang 21, -O0 (debug), server_config, 3.13.0: +36%; Apple clang 21, -O0 (debug), server_config, 3.13.0, precompiled header: -20%; Apple clang 21, -O0 (debug), server_config, 3.13.0, module: +8%; Apple clang 21, -O2, count_numbers, 3.13.0: +43%; Apple clang 21, -O2, count_numbers, 3.13.0, precompiled header: -1%; Apple clang 21, -O2, count_numbers, 3.13.0, module: +12%; Apple clang 21, -O2, server_config, 3.13.0: +42%; Apple clang 21, -O2, server_config, 3.13.0, precompiled header: +12%; Apple clang 21, -O2, server_config, 3.13.0, module: +22%; G&#8203;CC 16, -O0 (debug), count_numbers, 3.13.0: +68%; G&#8203;CC 16, -O0 (debug), count_numbers, 3.13.0, precompiled header: +12%; G&#8203;CC 16, -O0 (debug), count_numbers, 3.13.0, module: +13%; G&#8203;CC 16, -O0 (debug), server_config, 3.13.0: +50%; G&#8203;CC 16, -O0 (debug), server_config, 3.13.0, precompiled header: +15%; G&#8203;CC 16, -O0 (debug), server_config, 3.13.0, module: +16%; G&#8203;CC 16, -O2, count_numbers, 3.13.0: +60%; G&#8203;CC 16, -O2, count_numbers, 3.13.0, precompiled header: +28%; G&#8203;CC 16, -O2, count_numbers, 3.13.0, module: +27%; G&#8203;CC 16, -O2, server_config, 3.13.0: +52%; G&#8203;CC 16, -O2, server_config, 3.13.0, precompiled header: +29%; G&#8203;CC 16, -O2, server_config, 3.13.0, module: +31%.</desc>
<rect class="nj-charts-c2" x="8" y="6" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="26" y="16.5">3.13.0</text>
<rect class="nj-charts-c1" x="97.2" y="6" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="115.2" y="16.5">3.13.0, precompiled header</text>
<rect class="nj-charts-c3" x="350.4" y="6" width="12" height="12" rx="3"/>
<text class="nj-charts-leg" x="368.4" y="16.5">3.13.0, module</text>
<text class="nj-charts-tick" x="320.833" y="46">as fast as 3.12.0</text>
<text class="nj-charts-panel" x="8" y="68">Apple clang 21, -O0 (debug)</text>
<line class="nj-charts-grid" x1="184.167" y1="74" x2="184.167" y2="170"/>
<line class="nj-charts-grid" x1="252.5" y1="74" x2="252.5" y2="170"/>
<line class="nj-charts-grid" x1="389.167" y1="74" x2="389.167" y2="170"/>
<line class="nj-charts-grid" x1="457.5" y1="74" x2="457.5" y2="170"/>
<line class="nj-charts-grid" x1="525.833" y1="74" x2="525.833" y2="170"/>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="101" text-anchor="end">count_numbers</text>
<path class="nj-charts-c2" d="M320.833 78 H439.833 Q443.833 78 443.833 82 V85 Q443.833 89 439.833 89 H320.833 Z"><title>count_numbers, Apple clang 21, -O0 (debug), 3.13.0: 1,131 ms against 831 ms with 3.12.0 (+36%)</title></path>
<text class="nj-charts-val" x="448.833" y="87.5">+36%</text>
<path class="nj-charts-c1" d="M320.833 92 H246.25 Q242.25 92 242.25 96 V99 Q242.25 103 246.25 103 H320.833 Z"><title>count_numbers, Apple clang 21, -O0 (debug), 3.13.0, precompiled header: 639 ms against 831 ms with 3.12.0 (&#8722;23%)</title></path>
<text class="nj-charts-val" x="237.25" y="101.5" text-anchor="end">&#8722;23%</text>
<path class="nj-charts-c3" d="M320.833 106 H307.75 Q303.75 106 303.75 110 V113 Q303.75 117 307.75 117 H320.833 Z"><title>count_numbers, Apple clang 21, -O0 (debug), 3.13.0, module: 790 ms against 831 ms with 3.12.0 (&#8722;5%)</title></path>
<text class="nj-charts-val" x="298.75" y="115.5" text-anchor="end">&#8722;5%</text>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="150" text-anchor="end">server_config</text>
<path class="nj-charts-c2" d="M320.833 127 H439.833 Q443.833 127 443.833 131 V134 Q443.833 138 439.833 138 H320.833 Z"><title>server_config, Apple clang 21, -O0 (debug), 3.13.0: 1,312 ms against 963 ms with 3.12.0 (+36%)</title></path>
<text class="nj-charts-val" x="448.833" y="136.5">+36%</text>
<path class="nj-charts-c1" d="M320.833 141 H256.5 Q252.5 141 252.5 145 V148 Q252.5 152 256.5 152 H320.833 Z"><title>server_config, Apple clang 21, -O0 (debug), 3.13.0, precompiled header: 774 ms against 963 ms with 3.12.0 (&#8722;20%)</title></path>
<text class="nj-charts-val" x="247.5" y="150.5" text-anchor="end">&#8722;20%</text>
<path class="nj-charts-c3" d="M320.833 155 H344.167 Q348.167 155 348.167 159 V162 Q348.167 166 344.167 166 H320.833 Z"><title>server_config, Apple clang 21, -O0 (debug), 3.13.0, module: 1,036 ms against 963 ms with 3.12.0 (+8%)</title></path>
<text class="nj-charts-val" x="353.167" y="164.5">+8%</text>
<text class="nj-charts-panel" x="8" y="198">Apple clang 21, -O2</text>
<line class="nj-charts-grid" x1="184.167" y1="204" x2="184.167" y2="300"/>
<line class="nj-charts-grid" x1="252.5" y1="204" x2="252.5" y2="300"/>
<line class="nj-charts-grid" x1="389.167" y1="204" x2="389.167" y2="300"/>
<line class="nj-charts-grid" x1="457.5" y1="204" x2="457.5" y2="300"/>
<line class="nj-charts-grid" x1="525.833" y1="204" x2="525.833" y2="300"/>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="231" text-anchor="end">count_numbers</text>
<path class="nj-charts-c2" d="M320.833 208 H463.75 Q467.75 208 467.75 212 V215 Q467.75 219 463.75 219 H320.833 Z"><title>count_numbers, Apple clang 21, -O2, 3.13.0: 1,898 ms against 1,328 ms with 3.12.0 (+43%)</title></path>
<text class="nj-charts-val" x="472.75" y="217.5">+43%</text>
<path class="nj-charts-c1" d="M320.833 222 H320.833 Q317.417 222 317.417 225.417 V229.583 Q317.417 233 320.833 233 H320.833 Z"><title>count_numbers, Apple clang 21, -O2, 3.13.0, precompiled header: 1,312 ms against 1,328 ms with 3.12.0 (&#8722;1%)</title></path>
<text class="nj-charts-val" x="312.417" y="231.5" text-anchor="end">&#8722;1%</text>
<path class="nj-charts-c3" d="M320.833 236 H357.833 Q361.833 236 361.833 240 V243 Q361.833 247 357.833 247 H320.833 Z"><title>count_numbers, Apple clang 21, -O2, 3.13.0, module: 1,491 ms against 1,328 ms with 3.12.0 (+12%)</title></path>
<text class="nj-charts-val" x="366.833" y="245.5">+12%</text>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="280" text-anchor="end">server_config</text>
<path class="nj-charts-c2" d="M320.833 257 H460.333 Q464.333 257 464.333 261 V264 Q464.333 268 460.333 268 H320.833 Z"><title>server_config, Apple clang 21, -O2, 3.13.0: 2,251 ms against 1,584 ms with 3.12.0 (+42%)</title></path>
<text class="nj-charts-val" x="469.333" y="266.5">+42%</text>
<path class="nj-charts-c1" d="M320.833 271 H357.833 Q361.833 271 361.833 275 V278 Q361.833 282 357.833 282 H320.833 Z"><title>server_config, Apple clang 21, -O2, 3.13.0, precompiled header: 1,779 ms against 1,584 ms with 3.12.0 (+12%)</title></path>
<text class="nj-charts-val" x="366.833" y="280.5">+12%</text>
<path class="nj-charts-c3" d="M320.833 285 H392 Q396 285 396 289 V292 Q396 296 392 296 H320.833 Z"><title>server_config, Apple clang 21, -O2, 3.13.0, module: 1,926 ms against 1,584 ms with 3.12.0 (+22%)</title></path>
<text class="nj-charts-val" x="401" y="294.5">+22%</text>
<text class="nj-charts-panel" x="8" y="328">G&#8203;CC 16, -O0 (debug)</text>
<line class="nj-charts-grid" x1="184.167" y1="334" x2="184.167" y2="430"/>
<line class="nj-charts-grid" x1="252.5" y1="334" x2="252.5" y2="430"/>
<line class="nj-charts-grid" x1="389.167" y1="334" x2="389.167" y2="430"/>
<line class="nj-charts-grid" x1="457.5" y1="334" x2="457.5" y2="430"/>
<line class="nj-charts-grid" x1="525.833" y1="334" x2="525.833" y2="430"/>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="361" text-anchor="end">count_numbers</text>
<path class="nj-charts-c2" d="M320.833 338 H549.167 Q553.167 338 553.167 342 V345 Q553.167 349 549.167 349 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O0 (debug), 3.13.0: 2,385 ms against 1,416 ms with 3.12.0 (+68%)</title></path>
<text class="nj-charts-val" x="558.167" y="347.5">+68%</text>
<path class="nj-charts-c1" d="M320.833 352 H357.833 Q361.833 352 361.833 356 V359 Q361.833 363 357.833 363 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O0 (debug), 3.13.0, precompiled header: 1,593 ms against 1,416 ms with 3.12.0 (+12%)</title></path>
<text class="nj-charts-val" x="366.833" y="361.5">+12%</text>
<path class="nj-charts-c3" d="M320.833 366 H361.25 Q365.25 366 365.25 370 V373 Q365.25 377 361.25 377 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O0 (debug), 3.13.0, module: 1,604 ms against 1,416 ms with 3.12.0 (+13%)</title></path>
<text class="nj-charts-val" x="370.25" y="375.5">+13%</text>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="410" text-anchor="end">server_config</text>
<path class="nj-charts-c2" d="M320.833 387 H487.667 Q491.667 387 491.667 391 V394 Q491.667 398 487.667 398 H320.833 Z"><title>server_config, G&#8203;CC 16, -O0 (debug), 3.13.0: 2,820 ms against 1,878 ms with 3.12.0 (+50%)</title></path>
<text class="nj-charts-val" x="496.667" y="396.5">+50%</text>
<path class="nj-charts-c1" d="M320.833 401 H368.083 Q372.083 401 372.083 405 V408 Q372.083 412 368.083 412 H320.833 Z"><title>server_config, G&#8203;CC 16, -O0 (debug), 3.13.0, precompiled header: 2,152 ms against 1,878 ms with 3.12.0 (+15%)</title></path>
<text class="nj-charts-val" x="377.083" y="410.5">+15%</text>
<path class="nj-charts-c3" d="M320.833 415 H371.5 Q375.5 415 375.5 419 V422 Q375.5 426 371.5 426 H320.833 Z"><title>server_config, G&#8203;CC 16, -O0 (debug), 3.13.0, module: 2,180 ms against 1,878 ms with 3.12.0 (+16%)</title></path>
<text class="nj-charts-val" x="380.5" y="424.5">+16%</text>
<text class="nj-charts-panel" x="8" y="458">G&#8203;CC 16, -O2</text>
<line class="nj-charts-grid" x1="184.167" y1="464" x2="184.167" y2="560"/>
<line class="nj-charts-grid" x1="252.5" y1="464" x2="252.5" y2="560"/>
<line class="nj-charts-grid" x1="389.167" y1="464" x2="389.167" y2="560"/>
<line class="nj-charts-grid" x1="457.5" y1="464" x2="457.5" y2="560"/>
<line class="nj-charts-grid" x1="525.833" y1="464" x2="525.833" y2="560"/>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="491" text-anchor="end">count_numbers</text>
<path class="nj-charts-c2" d="M320.833 468 H521.833 Q525.833 468 525.833 472 V475 Q525.833 479 521.833 479 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O2, 3.13.0: 3,464 ms against 2,159 ms with 3.12.0 (+60%)</title></path>
<text class="nj-charts-val" x="530.833" y="477.5">+60%</text>
<path class="nj-charts-c1" d="M320.833 482 H412.5 Q416.5 482 416.5 486 V489 Q416.5 493 412.5 493 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O2, 3.13.0, precompiled header: 2,765 ms against 2,159 ms with 3.12.0 (+28%)</title></path>
<text class="nj-charts-val" x="421.5" y="491.5">+28%</text>
<path class="nj-charts-c3" d="M320.833 496 H409.083 Q413.083 496 413.083 500 V503 Q413.083 507 409.083 507 H320.833 Z"><title>count_numbers, G&#8203;CC 16, -O2, 3.13.0, module: 2,740 ms against 2,159 ms with 3.12.0 (+27%)</title></path>
<text class="nj-charts-val" x="418.083" y="505.5">+27%</text>
<text class="nj-charts-rowlabel nj-charts-code" x="142" y="540" text-anchor="end">server_config</text>
<path class="nj-charts-c2" d="M320.833 517 H494.5 Q498.5 517 498.5 521 V524 Q498.5 528 494.5 528 H320.833 Z"><title>server_config, G&#8203;CC 16, -O2, 3.13.0: 4,388 ms against 2,878 ms with 3.12.0 (+52%)</title></path>
<text class="nj-charts-val" x="503.5" y="526.5">+52%</text>
<path class="nj-charts-c1" d="M320.833 531 H415.917 Q419.917 531 419.917 535 V538 Q419.917 542 415.917 542 H320.833 Z"><title>server_config, G&#8203;CC 16, -O2, 3.13.0, precompiled header: 3,722 ms against 2,878 ms with 3.12.0 (+29%)</title></path>
<text class="nj-charts-val" x="424.917" y="540.5">+29%</text>
<path class="nj-charts-c3" d="M320.833 545 H422.75 Q426.75 545 426.75 549 V552 Q426.75 556 422.75 556 H320.833 Z"><title>server_config, G&#8203;CC 16, -O2, 3.13.0, module: 3,774 ms against 2,878 ms with 3.12.0 (+31%)</title></path>
<text class="nj-charts-val" x="431.75" y="554.5">+31%</text>
<line class="nj-charts-ref" x1="320.833" y1="52" x2="320.833" y2="574"/>
<text class="nj-charts-tick" x="184.167" y="590">&#8722;40%</text>
<text class="nj-charts-tick" x="252.5" y="590">&#8722;20%</text>
<text class="nj-charts-tick" x="320.833" y="590">0</text>
<text class="nj-charts-tick" x="389.167" y="590">+20%</text>
<text class="nj-charts-tick" x="457.5" y="590">+40%</text>
<text class="nj-charts-tick" x="525.833" y="590">+60%</text>
<text class="nj-charts-tick" x="355" y="608">compile time compared with 3.12.0, less is better</text>
</svg>

</div>

<p class="nj-caption" markdown>How much longer or shorter each program takes to compile than with 3.12.0, less is
better: Apple clang 21 and GCC 16.2, CPU time of the compiler, median of 5 interleaved runs, C++20, Apple M1 Max. The
one-off cost of building the precompiled header or the module is not included. Hover over a bar for the time in
milliseconds; [Appendix G](#g-how-we-measured) has all times, the programs, and the commands.</p>

3.13.0 takes 36–68% longer to compile these programs. A good part of that is reading the header, and a precompiled
header or a module does that once instead of in every translation unit:

- **In debug builds,** which are what you wait for while you edit, a precompiled 3.13.0 compiles faster than 3.12.0 with
  Apple clang, and within 12–15% of it with GCC.
- **In optimized builds,** less of the increase goes away, because the optimizer still works through all the code a
  program instantiates. A precompiled header or a module wins back 41% to all of it.
- **The one-off cost** is 0.9 s (Apple clang) or 2.3 s (GCC) to build the precompiled header, and 1.4 s or 2.3 s to
  build the module, once per set of compiler flags. A precompiled header pays for itself after two to four translation
  units, a module after three to six.
- **Modules have caveats.** Apple clang needs `-fcxx-modules`, [module support](../../features/modules.md) still depends
  heavily on the compiler version, and macros don't cross a module boundary: with `import nlohmann.json;`, the
  `NLOHMANN_DEFINE_TYPE_*` macros aren't available, which is why `server_config` writes `to_json()` and `from_json()` by
  hand.

The [compile-time page](../../integration/compile_times.md) measures these and the other options, such as including
`<nlohmann/json_fwd.hpp>` in headers that only name `json`, and
[`JSON_NO_AUTOMATIC_UDLS`](../../api/macros/json_no_automatic_udls.md). We did not measure binary size or peak memory.

## Summing up

Hardly any of the techniques in this post are new. What we think made the difference is their combination, under the
conditions of a header-only C++11 library whose API and output had to stay the same.

## Thanks

Most of what is in this post was invented by other people.

**Code we adapted.** The library contains code adapted from these four projects. We use it under the MIT License, and
the source files that contain it carry the authors' copyright lines and say what was taken; the
[README](https://github.com/nlohmann/json#license) lists them too.

- [fast_float](https://github.com/fastfloat/fast_float) (Apache-2.0, MIT, or BSL-1.0) by Daniel Lemire and contributors:
  the Eisel-Lemire algorithm, its table of powers of five, its digit comparison for long numbers, and its parsing of
  eight digits at a time (N. Mushtak and D. Lemire, ["Fast number parsing without
  fallback"](https://arxiv.org/abs/2212.06644), 2023). W. D. Clinger for the [fast
  path](https://doi.org/10.1145/93542.93557), M. Eisel for the algorithm.
- [Żmij](https://github.com/vitaut/zmij) (MIT) by Victor Zverovich, with the digit conversion of Xiang JunBo, the NEON
  sequence and compressed powers of ten of Dougall Johnson, and the SSE support of Tobias Schlüter: ported to C++11.
- [simdjson](https://github.com/simdjson/simdjson) (Apache-2.0 or MIT) by Daniel Lemire, Geoff Langdale, John Keiser,
  and contributors: the "lookup4" UTF-8 check and its tables (J. Keiser and D. Lemire, ["Validating UTF-8 In Less Than
  One Instruction Per Byte"](https://arxiv.org/abs/2010.03090), 2021), in `json.hpp`'s lexer and in `json_view.hpp`.
- [yyjson](https://github.com/ibireme/yyjson) (MIT) by YaoYuan: table-driven `\u` decoding and the unrolled checks at
  fixed offsets in `json_view.hpp`'s parser.

**Ideas we took.** From these we took the idea, not their code, in the order they appear above:

- [serde_json](https://github.com/serde-rs/json) (MIT or Apache-2.0): deriving positions from the offset only on error.
- Sean Eron Anderson's [Bit Twiddling Hacks](https://graphics.stanford.edu/~seander/bithacks.html) (snippets in the
  public domain): the zero-byte test behind every word-at-a-time scan.
- [Glaze](https://github.com/stephenberry/glaze) (MIT): skipping indentation in 8-byte steps (`skip_matching_ws`).
- [SQLite](https://sqlite.org) (public domain): writing short strings with a table loop, as its `jsonAppendString()`
  does.
- [orjson](https://github.com/ijl/orjson) (Apache-2.0 or MIT; its escape table MPL-2.0) and
  [sonic-rs](https://github.com/cloudwego/sonic-rs) (Apache-2.0), from which orjson adapted it: escape sequences as
  fixed-size table rows (`QUOTE_TAB`).
- [simdjson](https://github.com/simdjson/simdjson)'s tape and [yyjson](https://github.com/ibireme/yyjson)'s 16-byte
  immutable document: a flat index in document order instead of a tree.
- [Boost.JSON](https://github.com/boostorg/json) (BSL-1.0): switching to a hash table for large objects.
- [RapidJSON](https://github.com/Tencent/rapidjson) (MIT): recursion as the default, iterative parsing as an option.

I thank the people who sent or shaped pull requests:

- [@gregmarr](https://github.com/gregmarr) reviewed most of them and suggested the sized-sentinel fast path, the peek
  design for exact stream positions, one SIMD switch for the whole library, and the vector check of `json_view`'s
  strings on edit;
- [@veselink1](https://github.com/veselink1) and [@michaelsam94](https://github.com/michaelsam94) wrote the allocator
  and exception-safety fixes for the destructor that 3.13.0 [took over][5762]; the non-recursive destructor itself goes
  back to [a pull request](https://github.com/nlohmann/json/pull/1436) by [@nickaein](https://github.com/nickaein) in
  2019;
- [@commit-msuyog](https://github.com/commit-msuyog) gave the 128-bit multiplication behind Eisel-Lemire MSVC
  intrinsics;
- [@ayush-singh-0601](https://github.com/ayush-singh-0601) started the fix for deep values in the binary writers;
- [@avionicharshit-byte](https://github.com/avionicharshit-byte) made `diff()` linear for shrinking arrays;
- [@mvanslobbe](https://github.com/mvanslobbe) sped up the parser's separator check;
- [@alexprabhat99](https://github.com/alexprabhat99) removed the temporary values behind CBOR and MessagePack object
  keys.

`twitter.json`, `citm_catalog.json` and `canada.json` come from Milo Yip's
[nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark) (MIT).

## Appendix

### A. Test files

| file | size | what it is | what makes it hard |
| --- | --: | --- | --- |
| `twitter.json` | 632 KB | 100 tweets from Twitter's search API, with their users | strings: 58% of the bytes are keys and strings, 15% of the bytes are non-ASCII (almost all of it Japanese text), and 13,345 keys |
| `citm_catalog.json` | 1.7 MB | a concert hall's catalog of events, performances and seat categories, in French | structure: 21,388 small objects and arrays, 14,392 integers, keys that average 8 bytes, and 71% whitespace from indentation |
| `canada.json` | 2.3 MB | the outline of Canada in GeoJSON | numbers: 111,080 floating-point coordinates, most with 16 or 17 significant digits, in 56,045 arrays, and almost no whitespace |
| `jeopardy.json` | 56 MB | 216,930 Jeopardy! questions as one array of objects | size: 1.5 million short strings in objects of 7 members; far larger than the CPU caches |

<p class="nj-table-caption" markdown>The test files. The first three are from Milo Yip's
[nativejson-benchmark](https://github.com/miloyip/nativejson-benchmark). The counts are of the parsed values; the share
of whitespace, string, and non-ASCII bytes is of the file as distributed. Several changes target the indentation of
`citm_catalog.json`: in the timeline benchmark, a minified copy of it parses 1.9× as fast as with 3.12.0, against 3.4×
for the file as distributed.</p>

### B. 3.12.0 against 3.13.0

The rows of the first chart:

| workload | 3.12.0 | 3.13.0 | speedup | Intel |
| --- | --: | --: | --: | --: |
| `json::parse()` of `twitter.json` | 3.21 ms | 0.921 ms | 3.5× | 2.6× |
| `json::parse()` of `citm_catalog.json` | 7.40 ms | 1.45 ms | 5.1× | 3.5× |
| `json::parse()` of `canada.json` | 15.2 ms | 3.73 ms | 4.1× | 6.1× |
| `json::parse()` of `canada.json`, indented by 4 spaces | 34.2 ms | 4.61 ms | 7.4× | 8.0× |
| `ordered_json::parse()` of `citm_catalog.json` | 11.0 ms | 1.34 ms | 8.2× | 6.6× |
| `json::parse()` of `twitter.json` from an `std::ifstream` | 3.40 ms | 1.38 ms | 2.5× | 2.3× |
| `json::parse()` of `citm_catalog.json` from a `FILE*` | 35.0 ms | 2.34 ms | 14.9× | 5.7× |
| `json::accept()` of `citm_catalog.json` | 6.48 ms | 0.474 ms | 13.7× | 8.4× |
| `dump()` of `twitter.json` | 1.41 ms | 0.214 ms | 6.6× | 5.7× |
| `dump()` of `canada.json` | 6.71 ms | 2.31 ms | 2.9× | 3.3× |
| `dump(4)` of `citm_catalog.json` | 1.95 ms | 0.422 ms | 4.6× | 4.1× |
| `to_cbor()` of `twitter.json` | 0.637 ms | 0.144 ms | 4.4× | 6.7× |
| `from_cbor()` of `twitter.json` from memory | 3.09 ms | 0.879 ms | 3.5× | 2.8× |
| `from_cbor()` of `twitter.json` from a `FILE*` | 9.92 ms | 1.07 ms | 9.2× | 6.5× |
| `diff()` of `canada.json` with every eighth scalar changed | 39.2 ms | 3.75 ms | 10.4× | 11.2× |
| iterating over every value of `canada.json` | 0.874 ms | 0.445 ms | 2.0× | 2.0× |
| copying `citm_catalog.json` and destroying the copy | 1.65 ms | 1.49 ms | 1.11× | 1.12× |
| `==` of `citm_catalog.json` and a copy | 0.264 ms | 0.261 ms | 1.01× | 0.95× |

<p class="nj-table-caption" markdown>Time per call with 3.12.0 and 3.13.0, Google Benchmark suite on an Apple M1 Max,
median of 12 runs; the speedup is the old time divided by the new one. The Intel column is the speedup on the Intel
MacBook Pro of [Appendix G](#g-how-we-measured). The parse rows do not include destroying the result (the suite pauses
the timer for that).</p>

??? info "All 182 benchmarks of the suite"

    | benchmark | 3.12.0 | 3.13.0 | speedup | Intel |
    | --- | --: | --: | --: | --: |
    | `Accept/canada` | 12.8 ms | 1.34 ms | 9.51× | 13× |
    | `Accept/citm_catalog` | 6.48 ms | 474 µs | 13.7× | 8.45× |
    | `Accept/floats` | 114 ms | 17.2 ms | 6.63× | 12.2× |
    | `Accept/jeopardy` | 218 ms | 27.9 ms | 7.82× | 6.64× |
    | `Accept/signed_ints` | 116 ms | 23.4 ms | 4.96× | 4.99× |
    | `Accept/small_signed_ints` | 56.5 ms | 13.2 ms | 4.29× | 3.90× |
    | `Accept/twitter` | 2.49 ms | 234 µs | 10.6× | 6.89× |
    | `Accept/unsigned_ints` | 115 ms | 22.8 ms | 5.03× | 4.95× |
    | `BinaryToCbor/1024` | 315 ns | 108 ns | 2.92× | 3.67× |
    | `BinaryToCbor/128` | 266 ns | 114 ns | 2.33× | 2.27× |
    | `BinaryToCbor/16384` | 950 ns | 418 ns | 2.27× | 3.46× |
    | `BinaryToCbor/16` | 246 ns | 49.9 ns | 4.93× | 6.33× |
    | `BinaryToCbor/2048` | 340 ns | 127 ns | 2.68× | 3.74× |
    | `BinaryToCbor/256` | 280 ns | 91.8 ns | 3.05× | 3.33× |
    | `BinaryToCbor/32768` | 1.58 µs | 838 ns | 1.88× | 2.11× |
    | `BinaryToCbor/32` | 262 ns | 50.3 ns | 5.21× | 6.24× |
    | `BinaryToCbor/4096` | 432 ns | 174 ns | 2.48× | 3.48× |
    | `BinaryToCbor/512` | 297 ns | 102 ns | 2.91× | 3.02× |
    | `BinaryToCbor/64` | 259 ns | 84.3 ns | 3.08× | 3.78× |
    | `BinaryToCbor/8192` | 527 ns | 254 ns | 2.08× | 3.30× |
    | `BinaryToCbor/8` | 251 ns | 49.9 ns | 5.02× | 6.18× |
    | `Copy/canada` | 3.69 ms | 2.9 ms | 1.27× | 1.17× |
    | `Copy/citm_catalog` | 1.65 ms | 1.49 ms | 1.11× | 1.12× |
    | `Copy/twitter` | 811 µs | 729 µs | 1.11× | 1.14× |
    | `CopyAssign/canada` | 3.74 ms | 2.94 ms | 1.27× | 1.19× |
    | `CopyAssign/citm_catalog` | 1.65 ms | 1.54 ms | 1.08× | 1.12× |
    | `CopyAssign/twitter` | 818 µs | 752 µs | 1.09× | 1.07× |
    | `CopyOnly/canada` | 1.54 ms | 1.52 ms | 1.01× | 1.00× |
    | `CopyOnly/citm_catalog` | 755 µs | 795 µs | 0.95× | 0.93× |
    | `CopyOnly/twitter` | 407 µs | 410 µs | 0.99× | 1.02× |
    | `CopyRing/canada` | 3.75 ms | 2.93 ms | 1.28× | 1.20× |
    | `CopyRing/citm_catalog` | 1.75 ms | 1.55 ms | 1.13× | 1.20× |
    | `CopyRing/twitter` | 876 µs | 784 µs | 1.12× | 1.15× |
    | `DestroyOnly/canada` | 2.16 ms | 1.38 ms | 1.56× | 1.32× |
    | `DestroyOnly/citm_catalog` | 896 µs | 682 µs | 1.31× | 1.20× |
    | `DestroyOnly/twitter` | 406 µs | 327 µs | 1.24× | 1.15× |
    | `Diff/canada` | 39.2 ms | 3.75 ms | 10.4× | 11.2× |
    | `Diff/citm_catalog` | 6.92 ms | 1.09 ms | 6.33× | 7.78× |
    | `Diff/twitter` | 4.93 ms | 640 µs | 7.71× | 8.79× |
    | `Dump/canada / -` | 6.71 ms | 2.31 ms | 2.90× | 3.34× |
    | `Dump/canada / 4` | 8.82 ms | 3.03 ms | 2.91× | 2.82× |
    | `Dump/citm_catalog / -` | 1.39 ms | 296 µs | 4.71× | 3.93× |
    | `Dump/citm_catalog / 4` | 1.95 ms | 422 µs | 4.62× | 4.09× |
    | `Dump/floats / -` | 63.5 ms | 23.8 ms | 2.67× | 2.50× |
    | `Dump/floats / 4` | 72 ms | 24.7 ms | 2.92× | 2.71× |
    | `Dump/jeopardy / -` | 202 ms | 30.6 ms | 6.59× | 3.75× |
    | `Dump/jeopardy / 4` | 220 ms | 34.4 ms | 6.42× | 2.61× |
    | `Dump/signed_ints / -` | 23.7 ms | 10.7 ms | 2.21× | 1.44× |
    | `Dump/signed_ints / 4` | 32 ms | 11.4 ms | 2.82× | 2.01× |
    | `Dump/small_signed_ints / -` | 17.9 ms | 7.93 ms | 2.25× | 1.81× |
    | `Dump/small_signed_ints / 4` | 25.1 ms | 8.81 ms | 2.84× | 2.21× |
    | `Dump/twitter / -` | 1.41 ms | 214 µs | 6.60× | 5.75× |
    | `Dump/twitter / 4` | 1.59 ms | 249 µs | 6.38× | 5.18× |
    | `Dump/unsigned_ints / -` | 23.6 ms | 8.07 ms | 2.92× | 1.58× |
    | `Dump/unsigned_ints / 4` | 31.7 ms | 8.51 ms | 3.73× | 2.30× |
    | `Equal/canada` | 463 µs | 336 µs | 1.38× | 1.38× |
    | `Equal/citm_catalog` | 264 µs | 261 µs | 1.01× | 0.95× |
    | `Equal/twitter` | 139 µs | 129 µs | 1.08× | 1.02× |
    | `Flatten/canada` | 28.7 ms | 11.2 ms | 2.56× | 2.68× |
    | `Flatten/citm_catalog` | 6.44 ms | 3.01 ms | 2.14× | 2.45× |
    | `Flatten/twitter` | 3.53 ms | 2.05 ms | 1.72× | 2.19× |
    | `FlattenOrdered/citm_catalog` | 256 ms | 1.41 ms | 182× | 185× |
    | `FlattenOrdered/twitter` | 50 ms | 864 µs | 57.9× | 46.1× |
    | `FromBinaryBuffer/bjdata / canada` | 8.15 ms | 4.17 ms | 1.95× | 2.02× |
    | `FromBinaryBuffer/bjdata / twitter` | 3.18 ms | 893 µs | 3.56× | 2.87× |
    | `FromBinaryBuffer/bjdata_optimized / canada` | 8.74 ms | 2.42 ms | 3.61× | 3.51× |
    | `FromBinaryBuffer/bjdata_optimized / twitter` | 3.16 ms | 885 µs | 3.57× | 2.86× |
    | `FromBinaryBuffer/bson / canada` | 9.33 ms | 4.27 ms | 2.18× | 2.20× |
    | `FromBinaryBuffer/bson / citm_catalog` | 3.92 ms | 1.61 ms | 2.43× | 2.59× |
    | `FromBinaryBuffer/bson / twitter` | 3.18 ms | 910 µs | 3.49× | 3.08× |
    | `FromBinaryBuffer/cbor / canada` | 8.39 ms | 2.08 ms | 4.03× | 3.86× |
    | `FromBinaryBuffer/cbor / citm_catalog` | 3.71 ms | 1.32 ms | 2.81× | 2.81× |
    | `FromBinaryBuffer/cbor / floats` | 29.2 ms | 5.48 ms | 5.32× | 3.64× |
    | `FromBinaryBuffer/cbor / jeopardy` | 353 ms | 101 ms | 3.50× | 3.43× |
    | `FromBinaryBuffer/cbor / signed_ints` | 36 ms | 9.78 ms | 3.68× | 2.37× |
    | `FromBinaryBuffer/cbor / twitter` | 3.09 ms | 879 µs | 3.52× | 2.83× |
    | `FromBinaryBuffer/msgpack / canada` | 8.26 ms | 2.1 ms | 3.94× | 3.92× |
    | `FromBinaryBuffer/msgpack / citm_catalog` | 3.72 ms | 1.29 ms | 2.89× | 2.94× |
    | `FromBinaryBuffer/msgpack / jeopardy` | 357 ms | 96.9 ms | 3.68× | 3.51× |
    | `FromBinaryBuffer/msgpack / twitter` | 3.06 ms | 850 µs | 3.60× | 3.02× |
    | `FromBinaryBuffer/ubjson / canada` | 8.13 ms | 4.14 ms | 1.96× | 2.13× |
    | `FromBinaryBuffer/ubjson / citm_catalog` | 3.82 ms | 1.66 ms | 2.31× | 2.44× |
    | `FromBinaryBuffer/ubjson / jeopardy` | 366 ms | 101 ms | 3.61× | 3.40× |
    | `FromBinaryBuffer/ubjson / twitter` | 3.15 ms | 896 µs | 3.52× | 2.90× |
    | `FromBinaryBuffer/ubjson_optimized / canada` | 8.51 ms | 2.39 ms | 3.56× | 3.67× |
    | `FromBinaryBuffer/ubjson_optimized / twitter` | 3.12 ms | 882 µs | 3.54× | 2.88× |
    | `FromBinaryFile/bjdata / twitter` | 10.4 ms | 1.45 ms | 7.18× | 5.89× |
    | `FromBinaryFile/bson / twitter` | 10.3 ms | 1.24 ms | 8.33× | 6.21× |
    | `FromBinaryFile/cbor / canada` | 14.3 ms | 2.41 ms | 5.96× | 3.68× |
    | `FromBinaryFile/cbor / twitter` | 9.92 ms | 1.07 ms | 9.23× | 6.46× |
    | `FromBinaryFile/ubjson / canada` | 13.6 ms | 6.23 ms | 2.17× | 2.50× |
    | `FromBinaryFile/ubjson / twitter` | 10.5 ms | 1.46 ms | 7.20× | 5.90× |
    | `FromBinaryShape/containers / bjdata` | 14.3 ms | 7.24 ms | 1.98× | 2.05× |
    | `FromBinaryShape/containers / bson` | 17.4 ms | 7.98 ms | 2.18× | 2.20× |
    | `FromBinaryShape/containers / cbor` | 13.9 ms | 3.93 ms | 3.54× | 3.49× |
    | `FromBinaryShape/containers / msgpack` | 13.8 ms | 3.88 ms | 3.55× | 3.52× |
    | `FromBinaryShape/containers / ubjson_optimized` | 15 ms | 4.49 ms | 3.34× | 3.34× |
    | `FromBinaryShape/containers / ubjson` | 14.4 ms | 7.27 ms | 1.98× | 2.03× |
    | `FromBinaryShape/nested / bjdata` | 96.4 µs | 38.2 µs | 2.52× | 2.50× |
    | `FromBinaryShape/nested / bson` | 103 µs | 42.5 µs | 2.41× | 2.42× |
    | `FromBinaryShape/nested / cbor` | 93.8 µs | 35.4 µs | 2.65× | 2.57× |
    | `FromBinaryShape/nested / msgpack` | 92 µs | 34.9 µs | 2.64× | 2.60× |
    | `FromBinaryShape/nested / ubjson` | 96.5 µs | 37.9 µs | 2.54× | 2.50× |
    | `FromBinaryShape/scalars / bjdata` | 24.8 ms | 11.5 ms | 2.16× | 2.22× |
    | `FromBinaryShape/scalars / cbor` | 25.7 ms | 5.69 ms | 4.51× | 3.56× |
    | `FromBinaryShape/scalars / msgpack` | 24.4 ms | 5.57 ms | 4.39× | 3.69× |
    | `FromBinaryShape/scalars / ubjson` | 24.9 ms | 11.6 ms | 2.15× | 2.03× |
    | `FromCborChunkedString/10000 chunks` | 90.9 µs | 61.5 µs | 1.48× | 1.09× |
    | `FromMsgpack/canada` | 14.4 ms | 2.4 ms | 5.97× | 3.63× |
    | `FromMsgpack/citm_catalog` | 9.04 ms | 1.67 ms | 5.42× | 4.60× |
    | `FromMsgpack/floats` | 59.8 ms | 28.2 ms | 2.12× | 2.89× |
    | `FromMsgpack/jeopardy` | 1,140 ms | 112 ms | 10.2× | 6.80× |
    | `FromMsgpack/signed_ints` | 63.1 ms | 32.7 ms | 1.93× | 2.44× |
    | `FromMsgpack/small_signed_ints` | 63.4 ms | 35.3 ms | 1.80× | 2.33× |
    | `FromMsgpack/twitter` | 9.99 ms | 1.01 ms | 9.87× | 6.76× |
    | `FromMsgpack/unsigned_ints` | 56.1 ms | 28.2 ms | 1.99× | 2.77× |
    | `GetArray<std::array<int, 1000>>` | 2.24 µs | 641 ns | 3.50× | 5.38× |
    | `GetArray<std::deque<int>>` | 8.16 µs | 1.17 µs | 6.96× | 4.75× |
    | `GetArray<std::set<int>>` | 58.8 µs | 41.6 µs | 1.42× | 1.30× |
    | `GetArray<std::vector<int>>` | 6.73 µs | 671 ns | 10.0× | 4.10× |
    | `GetMap/citm_catalog` | 3.44 ms | 2.44 ms | 1.41× | 1.48× |
    | `GetVectorDouble/floats` | 6.7 ms | 651 µs | 10.3× | 2.98× |
    | `GetVectorInt/signed_ints` | 8.07 ms | 3.41 ms | 2.37× | 2.02× |
    | `Iterate/canada` | 874 µs | 445 µs | 1.96× | 2.02× |
    | `Iterate/citm_catalog` | 302 µs | 158 µs | 1.91× | 1.53× |
    | `Iterate/twitter` | 87.3 µs | 58.9 µs | 1.48× | 1.20× |
    | `JsonPointerAt/citm_catalog` | 1.85 ms | 1.16 ms | 1.60× | 1.47× |
    | `JsonPointerAt/twitter` | 791 µs | 600 µs | 1.32× | 1.14× |
    | `JsonPointerContains/citm_catalog` | 2.74 ms | 1.25 ms | 2.18× | 2.51× |
    | `JsonPointerContains/twitter` | 1.32 ms | 620 µs | 2.13× | 2.16× |
    | `JsonPointerParse/citm_catalog` | 5.73 ms | 2.21 ms | 2.59× | 3.74× |
    | `JsonPointerParse/twitter` | 2.47 ms | 1.01 ms | 2.45× | 3.18× |
    | `JsonPointerToString/citm_catalog` | 6.65 ms | 1.9 ms | 3.51× | 4.61× |
    | `JsonPointerToString/twitter` | 2.14 ms | 812 µs | 2.63× | 2.66× |
    | `ParseFILE/canada` | 52.9 ms | 6.02 ms | 8.79× | 5.46× |
    | `ParseFILE/citm_catalog` | 35 ms | 2.34 ms | 14.9× | 5.73× |
    | `ParseFILE/twitter` | 13.8 ms | 1.35 ms | 10.2× | 4.24× |
    | `ParseFile/canada` | 17.7 ms | 6.23 ms | 2.84× | 4.67× |
    | `ParseFile/citm_catalog` | 7.86 ms | 2.47 ms | 3.18× | 2.98× |
    | `ParseFile/floats` | 129 ms | 48.4 ms | 2.67× | 5.68× |
    | `ParseFile/jeopardy` | 330 ms | 156 ms | 2.12× | 2.23× |
    | `ParseFile/signed_ints` | 128 ms | 46.6 ms | 2.74× | 3.41× |
    | `ParseFile/small_signed_ints` | 64.5 ms | 33.4 ms | 1.93× | 2.57× |
    | `ParseFile/twitter` | 3.4 ms | 1.38 ms | 2.46× | 2.33× |
    | `ParseFile/unsigned_ints` | 123 ms | 47.3 ms | 2.61× | 3.52× |
    | `ParseIndented/canada / 4` | 34.2 ms | 4.61 ms | 7.41× | 8.02× |
    | `ParseIndented/citm_catalog / 4` | 7.45 ms | 1.46 ms | 5.11× | 3.49× |
    | `ParseIndented/jeopardy / 4` | 339 ms | 114 ms | 2.96× | 2.46× |
    | `ParseIndented/twitter / 4` | 3.61 ms | 975 µs | 3.70× | 2.60× |
    | `ParseStreamValues/ndjson` | 7.08 ms | 3.72 ms | 1.91× | 2.06× |
    | `ParseStreamValues/numbers` | 1.93 ms | 388 µs | 4.97× | 6.06× |
    | `ParseString/canada` | 15.2 ms | 3.73 ms | 4.08× | 6.13× |
    | `ParseString/citm_catalog` | 7.4 ms | 1.45 ms | 5.11× | 3.46× |
    | `ParseString/floats` | 120 ms | 25 ms | 4.80× | 8.68× |
    | `ParseString/jeopardy` | 303 ms | 113 ms | 2.68× | 2.32× |
    | `ParseString/signed_ints` | 121 ms | 28.7 ms | 4.22× | 4.29× |
    | `ParseString/small_signed_ints` | 60.8 ms | 17.7 ms | 3.43× | 3.38× |
    | `ParseString/twitter` | 3.21 ms | 921 µs | 3.49× | 2.60× |
    | `ParseString/unsigned_ints` | 120 ms | 28.5 ms | 4.21× | 4.23× |
    | `ParseStringOrdered/canada` | 15.3 ms | 3.78 ms | 4.04× | 6.21× |
    | `ParseStringOrdered/citm_catalog` | 11 ms | 1.34 ms | 8.18× | 6.59× |
    | `ParseStringOrdered/jeopardy` | 360 ms | 98.1 ms | 3.67× | 3.38× |
    | `ParseStringOrdered/twitter` | 4.41 ms | 804 µs | 5.49× | 4.93× |
    | `Patch/canada` | 10.1 ms | 3.41 ms | 2.97× | 2.46× |
    | `Patch/citm_catalog` | 2.54 ms | 1.65 ms | 1.54× | 1.38× |
    | `Patch/twitter` | 1.49 ms | 870 µs | 1.72× | 1.45× |
    | `SaxParse/canada` | 12.9 ms | 2.5 ms | 5.15× | 8.84× |
    | `SaxParse/citm_catalog` | 6.44 ms | 655 µs | 9.82× | 6.85× |
    | `SaxParse/twitter` | 2.49 ms | 334 µs | 7.45× | 5.91× |
    | `ToCbor/canada` | 1.39 ms | 555 µs | 2.51× | 2.27× |
    | `ToCbor/citm_catalog` | 1.03 ms | 260 µs | 3.97× | 5.60× |
    | `ToCbor/floats` | 8.94 ms | 1.85 ms | 4.84× | 1.94× |
    | `ToCbor/jeopardy` | 71.5 ms | 21.1 ms | 3.39× | 2.87× |
    | `ToCbor/signed_ints` | 11.4 ms | 2.74 ms | 4.15× | 1.83× |
    | `ToCbor/small_signed_ints` | 10.3 ms | 2.38 ms | 4.33× | 2.78× |
    | `ToCbor/twitter` | 637 µs | 144 µs | 4.41× | 6.67× |
    | `ToCbor/unsigned_ints` | 8.05 ms | 2.74 ms | 2.94× | 1.48× |
    | `ToJsonStrings/copy` | 5.86 ms | 5.6 ms | 1.05× | 1.05× |
    | `ToJsonStrings/move` | 5.92 ms | 3.05 ms | 1.94× | 1.78× |
    | `Unflatten/canada` | 41.8 ms | 10.8 ms | 3.86× | 4.32× |
    | `Unflatten/citm_catalog` | 9.8 ms | 3.54 ms | 2.77× | 3.32× |
    | `Unflatten/twitter` | 4.57 ms | 2.17 ms | 2.11× | 2.42× |

### C. The timeline

The other four workloads we followed:

- `accept()` of `twitter.json`: the lexer alone, since `accept()` only validates and builds nothing;
- `parse()` of `twitter.json` from an `std::ifstream`: reading from a stream instead of a string;
- `dump()` of `canada.json`: writing floating-point numbers;
- `to_cbor()` of `twitter.json`: writing a binary format.

<div class="nj-charts-grid-wrap" markdown>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-accept_twitter nj-blog-tl-accept_twitter-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-accept_twitter">accept() twitter.json: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-accept_twitter-d">accept() twitter.json: speedup over 3.12.0 at each of 360 commits, ending at 10x. Labeled steps, by theme: 4, 1, 4, 4, 2, 2, 1.</desc>
<text class="nj-charts-panel" x="8" y="18">accept() twitter.json</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="172.5" x2="330" y2="172.5"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="176.5">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="137" x2="330" y2="137"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="141">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="101.5" x2="330" y2="101.5"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="105.5">8&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">16&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.1 45.6,208.1 45.6,207.9 46.4,207.9 46.4,208.0 47.2,208.0 47.2,207.8 48.0,207.8 48.0,207.9 48.8,207.9 48.8,208.0 49.6,208.0 49.6,208.1 50.4,208.1 50.4,208.3 51.2,208.3 51.2,207.3 52.0,207.3 52.0,207.9 52.8,207.9 52.8,208.1 53.6,208.1 53.6,208.0 54.4,208.0 54.4,207.9 55.2,207.9 55.2,207.8 55.9,207.8 55.9,207.9 56.7,207.9 56.7,207.9 57.5,207.9 57.5,207.8 58.3,207.8 58.3,208.1 59.1,208.1 59.1,207.4 59.9,207.4 59.9,208.0 60.7,208.0 60.7,208.0 61.5,208.0 61.5,207.8 62.3,207.8 62.3,207.9 63.1,207.9 63.1,208.0 63.9,208.0 63.9,207.4 64.7,207.4 64.7,207.9 65.5,207.9 65.5,207.7 66.3,207.7 66.3,207.8 67.1,207.8 67.1,208.0 67.9,208.0 67.9,208.0 68.7,208.0 68.7,207.5 69.5,207.5 69.5,207.8 70.3,207.8 70.3,207.7 71.1,207.7 71.1,207.8 71.9,207.8 71.9,208.1 72.7,208.1 72.7,207.8 73.5,207.8 73.5,207.3 74.3,207.3 74.3,207.9 75.1,207.9 75.1,207.4 75.9,207.4 75.9,207.8 76.7,207.8 76.7,207.5 77.5,207.5 77.5,208.1 78.3,208.1 78.3,207.7 79.1,207.7 79.1,207.7 79.8,207.7 79.8,208.1 80.6,208.1 80.6,208.2 81.4,208.2 81.4,207.9 82.2,207.9 82.2,207.8 83.0,207.8 83.0,207.9 83.8,207.9 83.8,207.9 84.6,207.9 84.6,207.6 85.4,207.6 85.4,207.9 86.2,207.9 86.2,207.9 87.0,207.9 87.0,208.0 87.8,208.0 87.8,197.9 88.6,197.9 88.6,198.5 89.4,198.5 89.4,198.7 90.2,198.7 90.2,198.3 91.0,198.3 91.0,198.7 91.8,198.7 91.8,198.0 92.6,198.0 92.6,198.0 93.4,198.0 93.4,198.5 94.2,198.5 94.2,198.3 95.0,198.3 95.0,198.4 95.8,198.4 95.8,198.7 96.6,198.7 96.6,198.0 97.4,198.0 97.4,198.4 98.2,198.4 98.2,198.5 99.0,198.5 99.0,198.7 99.8,198.7 99.8,198.5 100.6,198.5 100.6,198.5 101.4,198.5 101.4,198.4 102.2,198.4 102.2,198.9 103.0,198.9 103.0,198.3 103.7,198.3 103.7,198.5 104.5,198.5 104.5,199.2 105.3,199.2 105.3,198.8 106.1,198.8 106.1,197.9 106.9,197.9 106.9,198.0 107.7,198.0 107.7,198.4 108.5,198.4 108.5,198.7 109.3,198.7 109.3,198.7 110.1,198.7 110.1,198.7 110.9,198.7 110.9,197.9 111.7,197.9 111.7,197.8 112.5,197.8 112.5,198.3 113.3,198.3 113.3,198.5 114.1,198.5 114.1,198.9 114.9,198.9 114.9,198.0 115.7,198.0 115.7,198.3 116.5,198.3 116.5,198.6 117.3,198.6 117.3,198.4 118.1,198.4 118.1,198.6 118.9,198.6 118.9,197.1 119.7,197.1 119.7,198.2 120.5,198.2 120.5,198.3 121.3,198.3 121.3,198.1 122.1,198.1 122.1,198.0 122.9,198.0 122.9,198.0 123.7,198.0 123.7,198.3 124.5,198.3 124.5,198.3 125.3,198.3 125.3,198.1 126.1,198.1 126.1,198.5 126.9,198.5 126.9,198.0 127.6,198.0 127.6,198.0 128.4,198.0 128.4,159.4 129.2,159.4 129.2,159.2 130.0,159.2 130.0,158.7 130.8,158.7 130.8,158.5 131.6,158.5 131.6,159.3 132.4,159.3 132.4,158.9 133.2,158.9 133.2,158.8 134.0,158.8 134.0,159.2 134.8,159.2 134.8,159.3 135.6,159.3 135.6,159.4 136.4,159.4 136.4,158.6 137.2,158.6 137.2,159.3 138.0,159.3 138.0,158.8 138.8,158.8 138.8,159.3 139.6,159.3 139.6,158.4 140.4,158.4 140.4,159.3 141.2,159.3 141.2,158.4 142.0,158.4 142.0,159.3 142.8,159.3 142.8,159.2 143.6,159.2 143.6,158.5 144.4,158.5 144.4,158.8 145.2,158.8 145.2,158.8 146.0,158.8 146.0,159.6 146.8,159.6 146.8,159.2 147.6,159.2 147.6,158.7 148.4,158.7 148.4,159.3 149.2,159.3 149.2,158.5 150.0,158.5 150.0,158.8 150.8,158.8 150.8,158.5 151.5,158.5 151.5,158.4 152.3,158.4 152.3,157.9 153.1,157.9 153.1,159.2 153.9,159.2 153.9,157.9 154.7,157.9 154.7,159.1 155.5,159.1 155.5,159.0 156.3,159.0 156.3,158.7 157.1,158.7 157.1,159.0 157.9,159.0 157.9,158.5 158.7,158.5 158.7,158.1 159.5,158.1 159.5,157.9 160.3,157.9 160.3,158.0 161.1,158.0 161.1,158.4 161.9,158.4 161.9,158.2 162.7,158.2 162.7,158.4 163.5,158.4 163.5,158.5 164.3,158.5 164.3,158.5 165.1,158.5 165.1,158.1 165.9,158.1 165.9,158.8 166.7,158.8 166.7,158.3 167.5,158.3 167.5,158.8 168.3,158.8 168.3,158.5 169.1,158.5 169.1,158.3 169.9,158.3 169.9,157.8 170.7,157.8 170.7,158.2 171.5,158.2 171.5,158.2 172.3,158.2 172.3,158.3 173.1,158.3 173.1,157.2 173.9,157.2 173.9,157.5 174.7,157.5 174.7,157.5 175.4,157.5 175.4,157.8 176.2,157.8 176.2,158.4 177.0,158.4 177.0,158.2 177.8,158.2 177.8,158.1 178.6,158.1 178.6,157.7 179.4,157.7 179.4,157.9 180.2,157.9 180.2,157.5 181.0,157.5 181.0,157.3 181.8,157.3 181.8,158.6 182.6,158.6 182.6,158.2 183.4,158.2 183.4,157.9 184.2,157.9 184.2,158.1 185.0,158.1 185.0,157.3 185.8,157.3 185.8,157.7 186.6,157.7 186.6,158.1 187.4,158.1 187.4,157.9 188.2,157.9 188.2,158.5 189.0,158.5 189.0,157.3 189.8,157.3 189.8,157.8 190.6,157.8 190.6,158.2 191.4,158.2 191.4,157.7 192.2,157.7 192.2,158.3 193.0,158.3 193.0,157.3 193.8,157.3 193.8,158.4 194.6,158.4 194.6,157.9 195.4,157.9 195.4,158.1 196.2,158.1 196.2,157.4 197.0,157.4 197.0,158.0 197.8,158.0 197.8,157.0 198.6,157.0 198.6,157.9 199.3,157.9 199.3,157.6 200.1,157.6 200.1,158.0 200.9,158.0 200.9,158.1 201.7,158.1 201.7,157.9 202.5,157.9 202.5,158.5 203.3,158.5 203.3,158.9 204.1,158.9 204.1,158.7 204.9,158.7 204.9,157.4 205.7,157.4 205.7,157.6 206.5,157.6 206.5,157.7 207.3,157.7 207.3,157.8 208.1,157.8 208.1,158.2 208.9,158.2 208.9,157.8 209.7,157.8 209.7,158.1 210.5,158.1 210.5,158.1 211.3,158.1 211.3,158.5 212.1,158.5 212.1,157.4 212.9,157.4 212.9,158.6 213.7,158.6 213.7,157.4 214.5,157.4 214.5,158.6 215.3,158.6 215.3,158.2 216.1,158.2 216.1,157.9 216.9,157.9 216.9,158.3 217.7,158.3 217.7,157.4 218.5,157.4 218.5,159.3 219.3,159.3 219.3,153.4 220.1,153.4 220.1,153.7 220.9,153.7 220.9,153.7 221.7,153.7 221.7,154.1 222.5,154.1 222.5,154.0 223.2,154.0 223.2,153.9 224.0,153.9 224.0,153.9 224.8,153.9 224.8,153.9 225.6,153.9 225.6,154.3 226.4,154.3 226.4,153.7 227.2,153.7 227.2,153.4 228.0,153.4 228.0,153.6 228.8,153.6 228.8,154.7 229.6,154.7 229.6,154.4 230.4,154.4 230.4,154.4 231.2,154.4 231.2,153.9 232.0,153.9 232.0,154.0 232.8,154.0 232.8,154.1 233.6,154.1 233.6,154.7 234.4,154.7 234.4,154.1 235.2,154.1 235.2,154.1 236.0,154.1 236.0,154.4 236.8,154.4 236.8,154.3 237.6,154.3 237.6,154.0 238.4,154.0 238.4,154.5 239.2,154.5 239.2,141.0 240.0,141.0 240.0,136.5 240.8,136.5 240.8,136.3 241.6,136.3 241.6,133.5 242.4,133.5 242.4,132.5 243.2,132.5 243.2,132.4 244.0,132.4 244.0,133.4 244.8,133.4 244.8,133.4 245.6,133.4 245.6,133.6 246.4,133.6 246.4,133.7 247.1,133.7 247.1,133.2 247.9,133.2 247.9,133.2 248.7,133.2 248.7,133.4 249.5,133.4 249.5,133.8 250.3,133.8 250.3,132.9 251.1,132.9 251.1,133.5 251.9,133.5 251.9,133.0 252.7,133.0 252.7,133.3 253.5,133.3 253.5,133.4 254.3,133.4 254.3,132.5 255.1,132.5 255.1,133.0 255.9,133.0 255.9,133.6 256.7,133.6 256.7,133.2 257.5,133.2 257.5,132.5 258.3,132.5 258.3,133.0 259.1,133.0 259.1,133.6 259.9,133.6 259.9,132.5 260.7,132.5 260.7,132.9 261.5,132.9 261.5,133.2 262.3,133.2 262.3,133.3 263.1,133.3 263.1,132.5 263.9,132.5 263.9,133.5 264.7,133.5 264.7,133.5 265.5,133.5 265.5,132.8 266.3,132.8 266.3,133.0 267.1,133.0 267.1,132.2 267.9,132.2 267.9,132.5 268.7,132.5 268.7,126.4 269.5,126.4 269.5,124.8 270.3,124.8 270.3,124.8 271.0,124.8 271.0,124.6 271.8,124.6 271.8,124.0 272.6,124.0 272.6,124.4 273.4,124.4 273.4,124.3 274.2,124.3 274.2,124.4 275.0,124.4 275.0,124.6 275.8,124.6 275.8,124.9 276.6,124.9 276.6,124.9 277.4,124.9 277.4,123.8 278.2,123.8 278.2,124.2 279.0,124.2 279.0,124.6 279.8,124.6 279.8,124.4 280.6,124.4 280.6,125.2 281.4,125.2 281.4,125.2 282.2,125.2 282.2,125.1 283.0,125.1 283.0,125.9 283.8,125.9 283.8,126.0 284.6,126.0 284.6,125.5 285.4,125.5 285.4,125.7 286.2,125.7 286.2,126.1 287.0,126.1 287.0,126.2 287.8,126.2 287.8,126.3 288.6,126.3 288.6,126.0 289.4,126.0 289.4,125.6 290.2,125.6 290.2,126.3 291.0,126.3 291.0,126.3 291.8,126.3 291.8,126.0 292.6,126.0 292.6,126.0 293.4,126.0 293.4,125.6 294.2,125.6 294.2,126.0 294.9,126.0 294.9,125.7 295.7,125.7 295.7,124.9 296.5,124.9 296.5,125.5 297.3,125.5 297.3,124.7 298.1,124.7 298.1,125.0 298.9,125.0 298.9,125.4 299.7,125.4 299.7,125.7 300.5,125.7 300.5,125.3 301.3,125.3 301.3,124.7 302.1,124.7 302.1,124.7 302.9,124.7 302.9,125.4 303.7,125.4 303.7,125.8 304.5,125.8 304.5,124.8 305.3,124.8 305.3,125.1 306.1,125.1 306.1,124.9 306.9,124.9 306.9,125.4 307.7,125.4 307.7,125.3 308.5,125.3 308.5,125.2 309.3,125.2 309.3,125.1 310.1,125.1 310.1,124.5 310.9,124.5 310.9,125.0 311.7,125.0 311.7,124.9 312.5,124.9 312.5,124.6 313.3,124.6 313.3,124.2 314.1,124.2 314.1,124.7 314.9,124.7 314.9,124.7 315.7,124.7 315.7,124.6 316.5,124.6 316.5,124.8 317.3,124.8 317.3,125.6 318.1,125.6 318.1,125.5 318.8,125.5 318.8,126.0 319.6,126.0 319.6,124.9 320.4,124.9 320.4,125.1 321.2,125.1 321.2,125.8 322.0,125.8 322.0,124.9 322.8,124.9 322.8,125.1 323.6,125.1 323.6,125.3 324.4,125.3 324.4,124.8 325.2,124.8 325.2,124.3 326.0,124.3 326.0,126.2 326.8,126.2 326.8,126.5 327.6,126.5 327.6,126.0 328.4,126.0 328.4,124.0 329.2,124.0 329.2,125.9 330.0,125.9 330.0,89.0"/>
<circle class="nj-charts-json-dot" cx="87.8" cy="197.9" r="3.5"><title>#5234: 1.22&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="87.8" y1="54.0" x2="87.8" y2="192.9"/>
<circle class="nj-theme-dot" cx="87.8" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="87.8" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="128.4" cy="159.4" r="3.5"><title>#5283: 2.6&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="128.4" y1="54.0" x2="128.4" y2="154.4"/>
<circle class="nj-theme-dot" cx="128.4" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="128.4" y="50.0" text-anchor="middle">1</text>
<circle class="nj-charts-json-dot" cx="219.3" cy="153.4" r="3.5"><title>#5592: 2.9&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="219.3" y1="54.0" x2="219.3" y2="148.4"/>
<circle class="nj-theme-dot" cx="219.3" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="219.3" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="239.2" cy="141.0" r="3.5"><title>#5809: 3.7&#215;</title></circle>
<circle class="nj-charts-json-dot" cx="240.0" cy="136.5" r="3.5"><title>#5810: 4.0&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="240.0" y1="36.0" x2="240.0" y2="131.5"/>
<circle class="nj-theme-dot" cx="231.0" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="231.0" y="32.0" text-anchor="middle">4</text>
<circle class="nj-theme-dot" cx="249.0" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="249.0" y="32.0" text-anchor="middle">2</text>
<circle class="nj-charts-json-dot" cx="268.7" cy="126.4" r="3.5"><title>#5853: 4.9&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="268.7" y1="54.0" x2="268.7" y2="121.4"/>
<circle class="nj-theme-dot" cx="268.7" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="268.7" y="50.0" text-anchor="middle">2</text>
<circle class="nj-charts-json-dot" cx="330.0" cy="89.0" r="3.5"><title>#6031: 10&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="330.0" y1="54.0" x2="330.0" y2="84.0"/>
<circle class="nj-theme-dot" cx="322.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="322.5" y="50.0" text-anchor="middle">1</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-parse_twitter_ifstream nj-blog-tl-parse_twitter_ifstream-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-parse_twitter_ifstream">parse() twitter.json, std::ifstream: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-parse_twitter_ifstream-d">parse() twitter.json, std::ifstream: speedup over 3.12.0 at each of 360 commits, ending at 2.2x. Labeled steps, by theme: 1, 1.</desc>
<text class="nj-charts-panel" x="8" y="18">parse() twitter.json, std::ifstream</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="137" x2="330" y2="137"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="141">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">4&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,209.3 45.6,209.3 45.6,206.6 46.4,206.6 46.4,208.3 47.2,208.3 47.2,205.9 48.0,205.9 48.0,209.3 48.8,209.3 48.8,208.3 49.6,208.3 49.6,207.9 50.4,207.9 50.4,209.4 51.2,209.4 51.2,205.8 52.0,205.8 52.0,206.7 52.8,206.7 52.8,209.2 53.6,209.2 53.6,208.1 54.4,208.1 54.4,206.9 55.2,206.9 55.2,207.5 55.9,207.5 55.9,207.5 56.7,207.5 56.7,207.6 57.5,207.6 57.5,206.9 58.3,206.9 58.3,206.9 59.1,206.9 59.1,208.4 59.9,208.4 59.9,208.6 60.7,208.6 60.7,209.1 61.5,209.1 61.5,207.7 62.3,207.7 62.3,207.0 63.1,207.0 63.1,206.7 63.9,206.7 63.9,206.1 64.7,206.1 64.7,207.5 65.5,207.5 65.5,206.4 66.3,206.4 66.3,206.7 67.1,206.7 67.1,206.8 67.9,206.8 67.9,209.3 68.7,209.3 68.7,206.7 69.5,206.7 69.5,206.8 70.3,206.8 70.3,206.6 71.1,206.6 71.1,206.8 71.9,206.8 71.9,209.2 72.7,209.2 72.7,207.6 73.5,207.6 73.5,205.9 74.3,205.9 74.3,209.1 75.1,209.1 75.1,206.6 75.9,206.6 75.9,207.4 76.7,207.4 76.7,207.0 77.5,207.0 77.5,209.1 78.3,209.1 78.3,205.8 79.1,205.8 79.1,206.9 79.8,206.9 79.8,208.0 80.6,208.0 80.6,208.5 81.4,208.5 81.4,206.6 82.2,206.6 82.2,206.0 83.0,206.0 83.0,207.9 83.8,207.9 83.8,206.6 84.6,206.6 84.6,206.5 85.4,206.5 85.4,206.6 86.2,206.6 86.2,207.2 87.0,207.2 87.0,208.0 87.8,208.0 87.8,208.1 88.6,208.1 88.6,206.7 89.4,206.7 89.4,207.8 90.2,207.8 90.2,206.7 91.0,206.7 91.0,208.1 91.8,208.1 91.8,205.9 92.6,205.9 92.6,206.8 93.4,206.8 93.4,208.0 94.2,208.0 94.2,207.3 95.0,207.3 95.0,206.7 95.8,206.7 95.8,209.3 96.6,209.3 96.6,206.5 97.4,206.5 97.4,207.2 98.2,207.2 98.2,208.2 99.0,208.2 99.0,209.3 99.8,209.3 99.8,207.8 100.6,207.8 100.6,206.9 101.4,206.9 101.4,206.7 102.2,206.7 102.2,209.0 103.0,209.0 103.0,208.0 103.7,208.0 103.7,208.1 104.5,208.1 104.5,209.1 105.3,209.1 105.3,208.1 106.1,208.1 106.1,205.6 106.9,205.6 106.9,207.0 107.7,207.0 107.7,206.7 108.5,206.7 108.5,207.9 109.3,207.9 109.3,206.7 110.1,206.7 110.1,206.9 110.9,206.9 110.9,206.8 111.7,206.8 111.7,206.4 112.5,206.4 112.5,207.1 113.3,207.1 113.3,208.6 114.1,208.6 114.1,208.7 114.9,208.7 114.9,206.6 115.7,206.6 115.7,209.3 116.5,209.3 116.5,208.0 117.3,208.0 117.3,206.7 118.1,206.7 118.1,207.7 118.9,207.7 118.9,206.9 119.7,206.9 119.7,208.8 120.5,208.8 120.5,208.7 121.3,208.7 121.3,207.7 122.1,207.7 122.1,208.8 122.9,208.8 122.9,207.8 123.7,207.8 123.7,210.3 124.5,210.3 124.5,208.9 125.3,208.9 125.3,208.9 126.1,208.9 126.1,209.0 126.9,209.0 126.9,208.0 127.6,208.0 127.6,207.7 128.4,207.7 128.4,208.3 129.2,208.3 129.2,207.0 130.0,207.0 130.0,207.2 130.8,207.2 130.8,207.5 131.6,207.5 131.6,208.0 132.4,208.0 132.4,207.6 133.2,207.6 133.2,207.9 134.0,207.9 134.0,207.6 134.8,207.6 134.8,208.5 135.6,208.5 135.6,209.2 136.4,209.2 136.4,206.3 137.2,206.3 137.2,208.7 138.0,208.7 138.0,207.6 138.8,207.6 138.8,207.4 139.6,207.4 139.6,207.5 140.4,207.5 140.4,209.0 141.2,209.0 141.2,206.9 142.0,206.9 142.0,209.3 142.8,209.3 142.8,209.9 143.6,209.9 143.6,207.0 144.4,207.0 144.4,207.3 145.2,207.3 145.2,208.1 146.0,208.1 146.0,209.8 146.8,209.8 146.8,208.1 147.6,208.1 147.6,208.1 148.4,208.1 148.4,208.5 149.2,208.5 149.2,208.2 150.0,208.2 150.0,210.4 150.8,210.4 150.8,207.7 151.5,207.7 151.5,207.2 152.3,207.2 152.3,206.7 153.1,206.7 153.1,209.9 153.9,209.9 153.9,206.6 154.7,206.6 154.7,209.9 155.5,209.9 155.5,208.8 156.3,208.8 156.3,208.8 157.1,208.8 157.1,209.5 157.9,209.5 157.9,208.9 158.7,208.9 158.7,206.4 159.5,206.4 159.5,207.2 160.3,207.2 160.3,207.0 161.1,207.0 161.1,207.2 161.9,207.2 161.9,206.6 162.7,206.6 162.7,207.2 163.5,207.2 163.5,208.0 164.3,208.0 164.3,207.6 165.1,207.6 165.1,207.9 165.9,207.9 165.9,207.5 166.7,207.5 166.7,205.6 167.5,205.6 167.5,208.0 168.3,208.0 168.3,209.7 169.1,209.7 169.1,207.9 169.9,207.9 169.9,207.6 170.7,207.6 170.7,208.5 171.5,208.5 171.5,207.9 172.3,207.9 172.3,210.4 173.1,210.4 173.1,206.7 173.9,206.7 173.9,207.7 174.7,207.7 174.7,209.2 175.4,209.2 175.4,206.8 176.2,206.8 176.2,209.3 177.0,209.3 177.0,208.0 177.8,208.0 177.8,208.0 178.6,208.0 178.6,207.9 179.4,207.9 179.4,208.2 180.2,208.2 180.2,207.9 181.0,207.9 181.0,207.0 181.8,207.0 181.8,208.8 182.6,208.8 182.6,208.0 183.4,208.0 183.4,208.0 184.2,208.0 184.2,209.2 185.0,209.2 185.0,206.7 185.8,206.7 185.8,206.7 186.6,206.7 186.6,208.5 187.4,208.5 187.4,208.9 188.2,208.9 188.2,210.1 189.0,210.1 189.0,206.4 189.8,206.4 189.8,209.4 190.6,209.4 190.6,210.1 191.4,210.1 191.4,207.6 192.2,207.6 192.2,209.5 193.0,209.5 193.0,208.7 193.8,208.7 193.8,211.1 194.6,211.1 194.6,210.1 195.4,210.1 195.4,211.7 196.2,211.7 196.2,208.8 197.0,208.8 197.0,209.2 197.8,209.2 197.8,207.7 198.6,207.7 198.6,208.1 199.3,208.1 199.3,206.4 200.1,206.4 200.1,206.7 200.9,206.7 200.9,207.3 201.7,207.3 201.7,207.8 202.5,207.8 202.5,208.7 203.3,208.7 203.3,210.1 204.1,210.1 204.1,210.0 204.9,210.0 204.9,206.9 205.7,206.9 205.7,209.0 206.5,209.0 206.5,208.7 207.3,208.7 207.3,209.1 208.1,209.1 208.1,208.6 208.9,208.6 208.9,208.9 209.7,208.9 209.7,207.3 210.5,207.3 210.5,208.9 211.3,208.9 211.3,209.2 212.1,209.2 212.1,207.3 212.9,207.3 212.9,210.5 213.7,210.5 213.7,207.5 214.5,207.5 214.5,207.9 215.3,207.9 215.3,209.4 216.1,209.4 216.1,207.5 216.9,207.5 216.9,209.0 217.7,209.0 217.7,207.7 218.5,207.7 218.5,209.4 219.3,209.4 219.3,207.7 220.1,207.7 220.1,210.1 220.9,210.1 220.9,208.7 221.7,208.7 221.7,208.7 222.5,208.7 222.5,211.1 223.2,211.1 223.2,208.8 224.0,208.8 224.0,210.9 224.8,210.9 224.8,209.5 225.6,209.5 225.6,210.4 226.4,210.4 226.4,210.2 227.2,210.2 227.2,208.8 228.0,208.8 228.0,210.4 228.8,210.4 228.8,211.6 229.6,211.6 229.6,211.5 230.4,211.5 230.4,209.5 231.2,209.5 231.2,209.4 232.0,209.4 232.0,209.2 232.8,209.2 232.8,208.8 233.6,208.8 233.6,210.0 234.4,210.0 234.4,209.1 235.2,209.1 235.2,208.0 236.0,208.0 236.0,209.3 236.8,209.3 236.8,208.1 237.6,208.1 237.6,209.0 238.4,209.0 238.4,211.5 239.2,211.5 239.2,210.6 240.0,210.6 240.0,210.5 240.8,210.5 240.8,210.0 241.6,210.0 241.6,210.2 242.4,210.2 242.4,208.7 243.2,208.7 243.2,209.0 244.0,209.0 244.0,208.9 244.8,208.9 244.8,210.0 245.6,210.0 245.6,211.7 246.4,211.7 246.4,210.1 247.1,210.1 247.1,209.1 247.9,209.1 247.9,208.8 248.7,208.8 248.7,209.1 249.5,209.1 249.5,206.9 250.3,206.9 250.3,205.9 251.1,205.9 251.1,208.6 251.9,208.6 251.9,206.1 252.7,206.1 252.7,207.0 253.5,207.0 253.5,206.5 254.3,206.5 254.3,204.8 255.1,204.8 255.1,206.3 255.9,206.3 255.9,206.7 256.7,206.7 256.7,207.1 257.5,207.1 257.5,206.4 258.3,206.4 258.3,138.8 259.1,138.8 259.1,140.7 259.9,140.7 259.9,140.3 260.7,140.3 260.7,141.1 261.5,141.1 261.5,143.1 262.3,143.1 262.3,140.7 263.1,140.7 263.1,140.2 263.9,140.2 263.9,141.7 264.7,141.7 264.7,143.4 265.5,143.4 265.5,143.0 266.3,143.0 266.3,141.0 267.1,141.0 267.1,140.4 267.9,140.4 267.9,142.0 268.7,142.0 268.7,141.8 269.5,141.8 269.5,138.4 270.3,138.4 270.3,134.8 271.0,134.8 271.0,137.0 271.8,137.0 271.8,133.2 272.6,133.2 272.6,132.9 273.4,132.9 273.4,133.2 274.2,133.2 274.2,132.6 275.0,132.6 275.0,127.0 275.8,127.0 275.8,124.4 276.6,124.4 276.6,126.3 277.4,126.3 277.4,123.9 278.2,123.9 278.2,126.7 279.0,126.7 279.0,128.5 279.8,128.5 279.8,124.5 280.6,124.5 280.6,124.2 281.4,124.2 281.4,124.9 282.2,124.9 282.2,124.8 283.0,124.8 283.0,125.1 283.8,125.1 283.8,127.3 284.6,127.3 284.6,124.2 285.4,124.2 285.4,125.1 286.2,125.1 286.2,127.0 287.0,127.0 287.0,125.2 287.8,125.2 287.8,127.1 288.6,127.1 288.6,125.0 289.4,125.0 289.4,127.1 290.2,127.1 290.2,128.9 291.0,128.9 291.0,129.4 291.8,129.4 291.8,126.9 292.6,126.9 292.6,127.4 293.4,127.4 293.4,127.0 294.2,127.0 294.2,127.4 294.9,127.4 294.9,125.8 295.7,125.8 295.7,125.7 296.5,125.7 296.5,126.6 297.3,126.6 297.3,125.1 298.1,125.1 298.1,127.2 298.9,127.2 298.9,129.2 299.7,129.2 299.7,126.0 300.5,126.0 300.5,126.5 301.3,126.5 301.3,125.5 302.1,125.5 302.1,125.2 302.9,125.2 302.9,127.9 303.7,127.9 303.7,128.3 304.5,128.3 304.5,125.0 305.3,125.0 305.3,125.9 306.1,125.9 306.1,125.5 306.9,125.5 306.9,126.4 307.7,126.4 307.7,125.6 308.5,125.6 308.5,125.0 309.3,125.0 309.3,128.7 310.1,128.7 310.1,124.8 310.9,124.8 310.9,126.1 311.7,126.1 311.7,125.9 312.5,125.9 312.5,125.2 313.3,125.2 313.3,126.3 314.1,126.3 314.1,125.5 314.9,125.5 314.9,125.8 315.7,125.8 315.7,126.0 316.5,126.0 316.5,125.6 317.3,125.6 317.3,128.4 318.1,128.4 318.1,127.3 318.8,127.3 318.8,128.8 319.6,128.8 319.6,123.9 320.4,123.9 320.4,125.4 321.2,125.4 321.2,126.9 322.0,126.9 322.0,125.9 322.8,125.9 322.8,124.8 323.6,124.8 323.6,125.2 324.4,125.2 324.4,125.2 325.2,125.2 325.2,124.9 326.0,124.9 326.0,126.6 326.8,126.6 326.8,127.5 327.6,127.5 327.6,125.1 328.4,125.1 328.4,124.0 329.2,124.0 329.2,123.7 330.0,123.7 330.0,125.2"/>
<circle class="nj-charts-json-dot" cx="258.3" cy="138.8" r="3.5"><title>#5828: 1.97&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="258.3" y1="54.0" x2="258.3" y2="133.8"/>
<circle class="nj-theme-dot" cx="258.3" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="258.3" y="50.0" text-anchor="middle">1</text>
<circle class="nj-charts-json-dot" cx="275.0" cy="127.0" r="3.5"><title>#5884: 2.2&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="275.0" y1="36.0" x2="275.0" y2="122.0"/>
<circle class="nj-theme-dot" cx="275.0" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="275.0" y="32.0" text-anchor="middle">1</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-dump_canada nj-blog-tl-dump_canada-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-dump_canada">dump() canada.json: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-dump_canada-d">dump() canada.json: speedup over 3.12.0 at each of 360 commits, ending at 3.2x. Labeled steps, by theme: 6, 3.</desc>
<text class="nj-charts-panel" x="8" y="18">dump() canada.json</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="160.667" x2="330" y2="160.667"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="164.667">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="113.333" x2="330" y2="113.333"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="117.333">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">8&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.0 45.6,208.0 45.6,207.2 46.4,207.2 46.4,207.9 47.2,207.9 47.2,206.7 48.0,206.7 48.0,207.5 48.8,207.5 48.8,207.7 49.6,207.7 49.6,207.3 50.4,207.3 50.4,207.9 51.2,207.9 51.2,206.6 52.0,206.6 52.0,207.5 52.8,207.5 52.8,208.0 53.6,208.0 53.6,207.6 54.4,207.6 54.4,207.2 55.2,207.2 55.2,207.5 55.9,207.5 55.9,206.6 56.7,206.6 56.7,207.1 57.5,207.1 57.5,207.1 58.3,207.1 58.3,207.2 59.1,207.2 59.1,206.6 59.9,206.6 59.9,207.5 60.7,207.5 60.7,207.6 61.5,207.6 61.5,207.7 62.3,207.7 62.3,207.2 63.1,207.2 63.1,206.5 63.9,206.5 63.9,206.8 64.7,206.8 64.7,207.1 65.5,207.1 65.5,207.0 66.3,207.0 66.3,207.1 67.1,207.1 67.1,206.7 67.9,206.7 67.9,208.2 68.7,208.2 68.7,207.5 69.5,207.5 69.5,206.6 70.3,206.6 70.3,206.7 71.1,206.7 71.1,206.3 71.9,206.3 71.9,208.4 72.7,208.4 72.7,207.3 73.5,207.3 73.5,206.8 74.3,206.8 74.3,208.0 75.1,208.0 75.1,207.8 75.9,207.8 75.9,207.1 76.7,207.1 76.7,207.5 77.5,207.5 77.5,207.9 78.3,207.9 78.3,206.3 79.1,206.3 79.1,206.8 79.8,206.8 79.8,207.5 80.6,207.5 80.6,208.1 81.4,208.1 81.4,206.6 82.2,206.6 82.2,207.2 83.0,207.2 83.0,207.2 83.8,207.2 83.8,207.4 84.6,207.4 84.6,207.0 85.4,207.0 85.4,206.7 86.2,206.7 86.2,206.5 87.0,206.5 87.0,207.6 87.8,207.6 87.8,207.4 88.6,207.4 88.6,207.2 89.4,207.2 89.4,207.5 90.2,207.5 90.2,207.6 91.0,207.6 91.0,208.0 91.8,208.0 91.8,208.2 92.6,208.2 92.6,206.7 93.4,206.7 93.4,207.4 94.2,207.4 94.2,206.7 95.0,206.7 95.0,206.6 95.8,206.6 95.8,208.0 96.6,208.0 96.6,208.0 97.4,208.0 97.4,206.3 98.2,206.3 98.2,208.3 99.0,208.3 99.0,207.8 99.8,207.8 99.8,207.4 100.6,207.4 100.6,206.3 101.4,206.3 101.4,208.1 102.2,208.1 102.2,207.5 103.0,207.5 103.0,207.4 103.7,207.4 103.7,207.5 104.5,207.5 104.5,207.7 105.3,207.7 105.3,208.0 106.1,208.0 106.1,207.0 106.9,207.0 106.9,207.5 107.7,207.5 107.7,207.2 108.5,207.2 108.5,207.7 109.3,207.7 109.3,207.3 110.1,207.3 110.1,208.0 110.9,208.0 110.9,206.7 111.7,206.7 111.7,206.6 112.5,206.6 112.5,207.2 113.3,207.2 113.3,208.1 114.1,208.1 114.1,208.1 114.9,208.1 114.9,206.7 115.7,206.7 115.7,207.8 116.5,207.8 116.5,207.6 117.3,207.6 117.3,207.4 118.1,207.4 118.1,207.1 118.9,207.1 118.9,207.5 119.7,207.5 119.7,208.8 120.5,208.8 120.5,209.2 121.3,209.2 121.3,208.4 122.1,208.4 122.1,208.3 122.9,208.3 122.9,208.0 123.7,208.0 123.7,209.0 124.5,209.0 124.5,208.5 125.3,208.5 125.3,209.1 126.1,209.1 126.1,209.2 126.9,209.2 126.9,208.6 127.6,208.6 127.6,207.7 128.4,207.7 128.4,207.7 129.2,207.7 129.2,207.5 130.0,207.5 130.0,202.2 130.8,202.2 130.8,202.3 131.6,202.3 131.6,201.7 132.4,201.7 132.4,202.3 133.2,202.3 133.2,201.9 134.0,201.9 134.0,201.2 134.8,201.2 134.8,202.1 135.6,202.1 135.6,202.6 136.4,202.6 136.4,201.5 137.2,201.5 137.2,202.3 138.0,202.3 138.0,202.3 138.8,202.3 138.8,201.7 139.6,201.7 139.6,201.3 140.4,201.3 140.4,202.5 141.2,202.5 141.2,201.1 142.0,201.1 142.0,202.9 142.8,202.9 142.8,202.2 143.6,202.2 143.6,201.7 144.4,201.7 144.4,201.7 145.2,201.7 145.2,201.6 146.0,201.6 146.0,203.0 146.8,203.0 146.8,202.7 147.6,202.7 147.6,202.4 148.4,202.4 148.4,202.8 149.2,202.8 149.2,202.1 150.0,202.1 150.0,203.1 150.8,203.1 150.8,202.3 151.5,202.3 151.5,202.3 152.3,202.3 152.3,201.8 153.1,201.8 153.1,203.1 153.9,203.1 153.9,201.8 154.7,201.8 154.7,202.6 155.5,202.6 155.5,202.6 156.3,202.6 156.3,202.9 157.1,202.9 157.1,202.3 157.9,202.3 157.9,202.3 158.7,202.3 158.7,201.6 159.5,201.6 159.5,201.5 160.3,201.5 160.3,202.4 161.1,202.4 161.1,201.7 161.9,201.7 161.9,201.2 162.7,201.2 162.7,202.2 163.5,202.2 163.5,201.6 164.3,201.6 164.3,201.6 165.1,201.6 165.1,201.8 165.9,201.8 165.9,202.1 166.7,202.1 166.7,201.7 167.5,201.7 167.5,201.4 168.3,201.4 168.3,202.2 169.1,202.2 169.1,202.7 169.9,202.7 169.9,202.4 170.7,202.4 170.7,201.7 171.5,201.7 171.5,201.7 172.3,201.7 172.3,202.3 173.1,202.3 173.1,201.6 173.9,201.6 173.9,201.7 174.7,201.7 174.7,202.2 175.4,202.2 175.4,202.2 176.2,202.2 176.2,202.4 177.0,202.4 177.0,201.7 177.8,201.7 177.8,202.1 178.6,202.1 178.6,201.6 179.4,201.6 179.4,202.2 180.2,202.2 180.2,201.9 181.0,201.9 181.0,201.9 181.8,201.9 181.8,202.5 182.6,202.5 182.6,201.6 183.4,201.6 183.4,202.1 184.2,202.1 184.2,202.3 185.0,202.3 185.0,201.8 185.8,201.8 185.8,201.5 186.6,201.5 186.6,202.3 187.4,202.3 187.4,202.2 188.2,202.2 188.2,202.9 189.0,202.9 189.0,201.3 189.8,201.3 189.8,202.2 190.6,202.2 190.6,203.6 191.4,203.6 191.4,201.9 192.2,201.9 192.2,202.4 193.0,202.4 193.0,201.7 193.8,201.7 193.8,202.7 194.6,202.7 194.6,202.3 195.4,202.3 195.4,202.5 196.2,202.5 196.2,202.1 197.0,202.1 197.0,203.4 197.8,203.4 197.8,202.1 198.6,202.1 198.6,202.3 199.3,202.3 199.3,201.9 200.1,201.9 200.1,202.3 200.9,202.3 200.9,201.7 201.7,201.7 201.7,202.4 202.5,202.4 202.5,202.3 203.3,202.3 203.3,202.9 204.1,202.9 204.1,202.9 204.9,202.9 204.9,202.2 205.7,202.2 205.7,202.4 206.5,202.4 206.5,202.2 207.3,202.2 207.3,202.7 208.1,202.7 208.1,202.5 208.9,202.5 208.9,202.5 209.7,202.5 209.7,201.5 210.5,201.5 210.5,203.1 211.3,203.1 211.3,203.2 212.1,203.2 212.1,201.5 212.9,201.5 212.9,203.3 213.7,203.3 213.7,202.4 214.5,202.4 214.5,201.8 215.3,201.8 215.3,202.5 216.1,202.5 216.1,201.7 216.9,201.7 216.9,202.1 217.7,202.1 217.7,202.0 218.5,202.0 218.5,202.9 219.3,202.9 219.3,202.1 220.1,202.1 220.1,202.6 220.9,202.6 220.9,202.3 221.7,202.3 221.7,202.4 222.5,202.4 222.5,202.9 223.2,202.9 223.2,201.9 224.0,201.9 224.0,203.4 224.8,203.4 224.8,202.3 225.6,202.3 225.6,202.3 226.4,202.3 226.4,202.7 227.2,202.7 227.2,202.5 228.0,202.5 228.0,202.3 228.8,202.3 228.8,203.8 229.6,203.8 229.6,202.7 230.4,202.7 230.4,202.1 231.2,202.1 231.2,202.0 232.0,202.0 232.0,202.7 232.8,202.7 232.8,201.9 233.6,201.9 233.6,202.0 234.4,202.0 234.4,202.3 235.2,202.3 235.2,202.7 236.0,202.7 236.0,201.6 236.8,201.6 236.8,202.1 237.6,202.1 237.6,202.3 238.4,202.3 238.4,203.0 239.2,203.0 239.2,202.7 240.0,202.7 240.0,202.9 240.8,202.9 240.8,203.1 241.6,203.1 241.6,202.6 242.4,202.6 242.4,130.7 243.2,130.7 243.2,130.0 244.0,130.0 244.0,130.6 244.8,130.6 244.8,130.9 245.6,130.9 245.6,130.9 246.4,130.9 246.4,130.8 247.1,130.8 247.1,130.5 247.9,130.5 247.9,130.8 248.7,130.8 248.7,130.7 249.5,130.7 249.5,130.7 250.3,130.7 250.3,130.3 251.1,130.3 251.1,131.1 251.9,131.1 251.9,131.0 252.7,131.0 252.7,130.7 253.5,130.7 253.5,131.0 254.3,131.0 254.3,130.1 255.1,130.1 255.1,129.5 255.9,129.5 255.9,130.8 256.7,130.8 256.7,131.1 257.5,131.1 257.5,130.2 258.3,130.2 258.3,130.0 259.1,130.0 259.1,129.9 259.9,129.9 259.9,130.1 260.7,130.1 260.7,129.9 261.5,129.9 261.5,129.6 262.3,129.6 262.3,129.9 263.1,129.9 263.1,130.5 263.9,130.5 263.9,130.5 264.7,130.5 264.7,130.7 265.5,130.7 265.5,130.0 266.3,130.0 266.3,130.0 267.1,130.0 267.1,130.3 267.9,130.3 267.9,130.4 268.7,130.4 268.7,131.1 269.5,131.1 269.5,130.5 270.3,130.5 270.3,130.5 271.0,130.5 271.0,131.4 271.8,131.4 271.8,129.8 272.6,129.8 272.6,131.0 273.4,131.0 273.4,130.3 274.2,130.3 274.2,130.5 275.0,130.5 275.0,131.1 275.8,131.1 275.8,130.3 276.6,130.3 276.6,126.5 277.4,126.5 277.4,127.2 278.2,127.2 278.2,127.8 279.0,127.8 279.0,127.4 279.8,127.4 279.8,126.5 280.6,126.5 280.6,127.2 281.4,127.2 281.4,126.4 282.2,126.4 282.2,126.7 283.0,126.7 283.0,126.9 283.8,126.9 283.8,127.0 284.6,127.0 284.6,126.5 285.4,126.5 285.4,126.9 286.2,126.9 286.2,126.8 287.0,126.8 287.0,126.0 287.8,126.0 287.8,127.6 288.6,127.6 288.6,126.7 289.4,126.7 289.4,126.6 290.2,126.6 290.2,127.3 291.0,127.3 291.0,127.3 291.8,127.3 291.8,127.2 292.6,127.2 292.6,127.4 293.4,127.4 293.4,127.5 294.2,127.5 294.2,127.2 294.9,127.2 294.9,127.6 295.7,127.6 295.7,126.6 296.5,126.6 296.5,127.3 297.3,127.3 297.3,127.1 298.1,127.1 298.1,127.8 298.9,127.8 298.9,128.4 299.7,128.4 299.7,127.6 300.5,127.6 300.5,126.7 301.3,126.7 301.3,127.2 302.1,127.2 302.1,127.0 302.9,127.0 302.9,127.7 303.7,127.7 303.7,128.4 304.5,128.4 304.5,126.9 305.3,126.9 305.3,127.1 306.1,127.1 306.1,127.4 306.9,127.4 306.9,127.4 307.7,127.4 307.7,127.0 308.5,127.0 308.5,126.7 309.3,126.7 309.3,127.7 310.1,127.7 310.1,126.9 310.9,126.9 310.9,127.4 311.7,127.4 311.7,127.2 312.5,127.2 312.5,126.9 313.3,126.9 313.3,127.0 314.1,127.0 314.1,127.4 314.9,127.4 314.9,127.3 315.7,127.3 315.7,127.4 316.5,127.4 316.5,127.5 317.3,127.5 317.3,128.1 318.1,128.1 318.1,127.3 318.8,127.3 318.8,127.7 319.6,127.7 319.6,126.9 320.4,126.9 320.4,127.0 321.2,127.0 321.2,128.6 322.0,128.6 322.0,127.0 322.8,127.0 322.8,128.3 323.6,128.3 323.6,127.8 324.4,127.8 324.4,126.8 325.2,126.8 325.2,127.6 326.0,127.6 326.0,127.5 326.8,127.5 326.8,127.9 327.6,127.9 327.6,127.5 328.4,127.5 328.4,127.8 329.2,127.8 329.2,127.5 330.0,127.5 330.0,127.6"/>
<circle class="nj-charts-json-dot" cx="130.0" cy="202.2" r="3.5"><title>#5285: 1.09&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="130.0" y1="54.0" x2="130.0" y2="197.2"/>
<circle class="nj-theme-dot" cx="130.0" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="130.0" y="50.0" text-anchor="middle">6</text>
<circle class="nj-charts-json-dot" cx="242.4" cy="130.7" r="3.5"><title>#5634: 3.1&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="242.4" y1="54.0" x2="242.4" y2="125.7"/>
<circle class="nj-theme-dot" cx="242.4" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="242.4" y="50.0" text-anchor="middle">3</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--timeline" viewBox="0 0 340 270" role="img" aria-labelledby="nj-blog-tl-to_cbor_twitter nj-blog-tl-to_cbor_twitter-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-tl-to_cbor_twitter">to_cbor() twitter: speedup over 3.12.0 by commit</title>
<desc id="nj-blog-tl-to_cbor_twitter-d">to_cbor() twitter: speedup over 3.12.0 at each of 360 commits, ending at 5.1x. Labeled steps, by theme: 4, 6, 6.</desc>
<text class="nj-charts-panel" x="8" y="18">to_cbor() twitter</text>
<line class="nj-charts-grid" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="212">1&#215;</text>
<line class="nj-charts-grid" x1="44" y1="160.667" x2="330" y2="160.667"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="164.667">2&#215;</text>
<line class="nj-charts-grid" x1="44" y1="113.333" x2="330" y2="113.333"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="117.333">4&#215;</text>
<line class="nj-charts-grid" x1="44" y1="66" x2="330" y2="66"/>
<text class="nj-charts-tick nj-charts-tick--r" x="38" y="70">8&#215;</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="44" y2="212"/>
<text class="nj-charts-tick" x="44" y="225">3.12.0</text>
<line class="nj-charts-axis" x1="116.496" y1="208" x2="116.496" y2="212"/>
<text class="nj-charts-tick" x="116.496" y="225">Sep 2026</text>
<line class="nj-charts-axis" x1="195.365" y1="208" x2="195.365" y2="212"/>
<text class="nj-charts-tick" x="195.365" y="225">Oct</text>
<line class="nj-charts-axis" x1="302.117" y1="208" x2="302.117" y2="212"/>
<text class="nj-charts-tick" x="302.117" y="225">Nov</text>
<polyline class="nj-charts-json" points="44.0,208.0 44.8,208.0 44.8,208.0 45.6,208.0 45.6,204.9 46.4,204.9 46.4,205.2 47.2,205.2 47.2,204.7 48.0,204.7 48.0,205.2 48.8,205.2 48.8,205.0 49.6,205.0 49.6,204.9 50.4,204.9 50.4,205.0 51.2,205.0 51.2,205.0 52.0,205.0 52.0,205.1 52.8,205.1 52.8,205.4 53.6,205.4 53.6,205.0 54.4,205.0 54.4,205.2 55.2,205.2 55.2,211.6 55.9,211.6 55.9,206.8 56.7,206.8 56.7,204.2 57.5,204.2 57.5,207.6 58.3,207.6 58.3,204.1 59.1,204.1 59.1,203.8 59.9,203.8 59.9,204.2 60.7,204.2 60.7,205.1 61.5,205.1 61.5,204.4 62.3,204.4 62.3,204.3 63.1,204.3 63.1,204.0 63.9,204.0 63.9,202.7 64.7,202.7 64.7,204.2 65.5,204.2 65.5,204.2 66.3,204.2 66.3,204.2 67.1,204.2 67.1,204.4 67.9,204.4 67.9,206.2 68.7,206.2 68.7,204.3 69.5,204.3 69.5,204.1 70.3,204.1 70.3,204.3 71.1,204.3 71.1,204.3 71.9,204.3 71.9,204.3 72.7,204.3 72.7,204.3 73.5,204.3 73.5,204.4 74.3,204.4 74.3,204.8 75.1,204.8 75.1,208.4 75.9,208.4 75.9,203.5 76.7,203.5 76.7,206.2 77.5,206.2 77.5,204.4 78.3,204.4 78.3,203.2 79.1,203.2 79.1,204.1 79.8,204.1 79.8,204.2 80.6,204.2 80.6,203.7 81.4,203.7 81.4,204.2 82.2,204.2 82.2,203.2 83.0,203.2 83.0,204.2 83.8,204.2 83.8,204.4 84.6,204.4 84.6,203.8 85.4,203.8 85.4,204.4 86.2,204.4 86.2,204.7 87.0,204.7 87.0,204.6 87.8,204.6 87.8,208.7 88.6,208.7 88.6,205.2 89.4,205.2 89.4,205.5 90.2,205.5 90.2,205.2 91.0,205.2 91.0,205.3 91.8,205.3 91.8,206.8 92.6,206.8 92.6,204.6 93.4,204.6 93.4,205.5 94.2,205.5 94.2,205.1 95.0,205.1 95.0,204.7 95.8,204.7 95.8,205.7 96.6,205.7 96.6,205.0 97.4,205.0 97.4,204.9 98.2,204.9 98.2,206.5 99.0,206.5 99.0,205.6 99.8,205.6 99.8,205.0 100.6,205.0 100.6,209.2 101.4,209.2 101.4,205.9 102.2,205.9 102.2,206.5 103.0,206.5 103.0,205.5 103.7,205.5 103.7,205.3 104.5,205.3 104.5,205.3 105.3,205.3 105.3,205.1 106.1,205.1 106.1,204.4 106.9,204.4 106.9,204.6 107.7,204.6 107.7,204.8 108.5,204.8 108.5,204.2 109.3,204.2 109.3,203.8 110.1,203.8 110.1,204.4 110.9,204.4 110.9,202.8 111.7,202.8 111.7,203.5 112.5,203.5 112.5,204.0 113.3,204.0 113.3,204.3 114.1,204.3 114.1,202.9 114.9,202.9 114.9,203.3 115.7,203.3 115.7,204.4 116.5,204.4 116.5,204.5 117.3,204.5 117.3,204.1 118.1,204.1 118.1,208.3 118.9,208.3 118.9,203.8 119.7,203.8 119.7,207.0 120.5,207.0 120.5,205.9 121.3,205.9 121.3,205.4 122.1,205.4 122.1,205.3 122.9,205.3 122.9,205.8 123.7,205.8 123.7,205.4 124.5,205.4 124.5,205.6 125.3,205.6 125.3,206.3 126.1,206.3 126.1,205.5 126.9,205.5 126.9,204.8 127.6,204.8 127.6,204.6 128.4,204.6 128.4,206.1 129.2,206.1 129.2,204.6 130.0,204.6 130.0,204.1 130.8,204.1 130.8,204.3 131.6,204.3 131.6,205.6 132.4,205.6 132.4,203.9 133.2,203.9 133.2,204.0 134.0,204.0 134.0,203.9 134.8,203.9 134.8,204.6 135.6,204.6 135.6,204.1 136.4,204.1 136.4,203.9 137.2,203.9 137.2,204.8 138.0,204.8 138.0,203.2 138.8,203.2 138.8,203.3 139.6,203.3 139.6,204.7 140.4,204.7 140.4,208.3 141.2,208.3 141.2,204.3 142.0,204.3 142.0,207.4 142.8,207.4 142.8,204.4 143.6,204.4 143.6,208.2 144.4,208.2 144.4,205.0 145.2,205.0 145.2,204.9 146.0,204.9 146.0,208.8 146.8,208.8 146.8,207.9 147.6,207.9 147.6,206.2 148.4,206.2 148.4,204.2 149.2,204.2 149.2,204.1 150.0,204.1 150.0,204.2 150.8,204.2 150.8,202.2 151.5,202.2 151.5,205.6 152.3,205.6 152.3,203.0 153.1,203.0 153.1,203.4 153.9,203.4 153.9,202.7 154.7,202.7 154.7,203.6 155.5,203.6 155.5,203.3 156.3,203.3 156.3,203.2 157.1,203.2 157.1,204.9 157.9,204.9 157.9,202.9 158.7,202.9 158.7,202.2 159.5,202.2 159.5,202.5 160.3,202.5 160.3,202.9 161.1,202.9 161.1,202.9 161.9,202.9 161.9,202.3 162.7,202.3 162.7,202.9 163.5,202.9 163.5,203.7 164.3,203.7 164.3,204.1 165.1,204.1 165.1,203.9 165.9,203.9 165.9,203.7 166.7,203.7 166.7,203.3 167.5,203.3 167.5,203.8 168.3,203.8 168.3,205.0 169.1,205.0 169.1,208.0 169.9,208.0 169.9,205.1 170.7,205.1 170.7,206.5 171.5,206.5 171.5,205.4 172.3,205.4 172.3,205.4 173.1,205.4 173.1,207.0 173.9,207.0 173.9,204.9 174.7,204.9 174.7,205.4 175.4,205.4 175.4,203.6 176.2,203.6 176.2,205.7 177.0,205.7 177.0,204.5 177.8,204.5 177.8,205.0 178.6,205.0 178.6,205.2 179.4,205.2 179.4,204.9 180.2,204.9 180.2,204.5 181.0,204.5 181.0,204.9 181.8,204.9 181.8,205.3 182.6,205.3 182.6,203.9 183.4,203.9 183.4,204.8 184.2,204.8 184.2,204.8 185.0,204.8 185.0,203.6 185.8,203.6 185.8,203.4 186.6,203.4 186.6,203.8 187.4,203.8 187.4,205.1 188.2,205.1 188.2,205.5 189.0,205.5 189.0,204.0 189.8,204.0 189.8,204.9 190.6,204.9 190.6,205.0 191.4,205.0 191.4,206.4 192.2,206.4 192.2,205.1 193.0,205.1 193.0,204.5 193.8,204.5 193.8,204.8 194.6,204.8 194.6,205.2 195.4,205.2 195.4,205.0 196.2,205.0 196.2,204.6 197.0,204.6 197.0,203.9 197.8,203.9 197.8,203.5 198.6,203.5 198.6,203.6 199.3,203.6 199.3,204.2 200.1,204.2 200.1,205.9 200.9,205.9 200.9,205.2 201.7,205.2 201.7,204.8 202.5,204.8 202.5,207.3 203.3,207.3 203.3,205.2 204.1,205.2 204.1,208.6 204.9,208.6 204.9,204.3 205.7,204.3 205.7,203.9 206.5,203.9 206.5,203.2 207.3,203.2 207.3,203.9 208.1,203.9 208.1,205.9 208.9,205.9 208.9,204.8 209.7,204.8 209.7,204.7 210.5,204.7 210.5,203.6 211.3,203.6 211.3,203.7 212.1,203.7 212.1,208.2 212.9,208.2 212.9,208.4 213.7,208.4 213.7,208.2 214.5,208.2 214.5,208.1 215.3,208.1 215.3,208.5 216.1,208.5 216.1,209.0 216.9,209.0 216.9,208.3 217.7,208.3 217.7,208.6 218.5,208.6 218.5,205.4 219.3,205.4 219.3,205.3 220.1,205.3 220.1,206.0 220.9,206.0 220.9,206.2 221.7,206.2 221.7,205.9 222.5,205.9 222.5,206.3 223.2,206.3 223.2,208.4 224.0,208.4 224.0,209.0 224.8,209.0 224.8,208.9 225.6,208.9 225.6,209.3 226.4,209.3 226.4,210.4 227.2,210.4 227.2,207.9 228.0,207.9 228.0,208.1 228.8,208.1 228.8,208.2 229.6,208.2 229.6,208.8 230.4,208.8 230.4,208.6 231.2,208.6 231.2,153.7 232.0,153.7 232.0,153.8 232.8,153.8 232.8,153.8 233.6,153.8 233.6,153.3 234.4,153.3 234.4,153.6 235.2,153.6 235.2,156.0 236.0,156.0 236.0,156.0 236.8,156.0 236.8,155.9 237.6,155.9 237.6,156.0 238.4,156.0 238.4,156.3 239.2,156.3 239.2,154.1 240.0,154.1 240.0,154.0 240.8,154.0 240.8,153.8 241.6,153.8 241.6,156.1 242.4,156.1 242.4,155.8 243.2,155.8 243.2,154.2 244.0,154.2 244.0,154.1 244.8,154.1 244.8,154.3 245.6,154.3 245.6,154.2 246.4,154.2 246.4,154.2 247.1,154.2 247.1,154.1 247.9,154.1 247.9,153.7 248.7,153.7 248.7,153.9 249.5,153.9 249.5,154.4 250.3,154.4 250.3,156.0 251.1,156.0 251.1,156.5 251.9,156.5 251.9,156.8 252.7,156.8 252.7,156.3 253.5,156.3 253.5,156.1 254.3,156.1 254.3,155.6 255.1,155.6 255.1,156.0 255.9,156.0 255.9,156.4 256.7,156.4 256.7,156.2 257.5,156.2 257.5,155.8 258.3,155.8 258.3,155.1 259.1,155.1 259.1,156.8 259.9,156.8 259.9,155.4 260.7,155.4 260.7,155.9 261.5,155.9 261.5,155.9 262.3,155.9 262.3,155.9 263.1,155.9 263.1,155.3 263.9,155.3 263.9,155.8 264.7,155.8 264.7,156.0 265.5,156.0 265.5,123.4 266.3,123.4 266.3,123.3 267.1,123.3 267.1,123.1 267.9,123.1 267.9,125.9 268.7,125.9 268.7,125.8 269.5,125.8 269.5,125.4 270.3,125.4 270.3,123.0 271.0,123.0 271.0,123.6 271.8,123.6 271.8,123.0 272.6,123.0 272.6,123.0 273.4,123.0 273.4,122.4 274.2,122.4 274.2,123.2 275.0,123.2 275.0,123.4 275.8,123.4 275.8,123.2 276.6,123.2 276.6,123.1 277.4,123.1 277.4,96.9 278.2,96.9 278.2,97.9 279.0,97.9 279.0,98.3 279.8,98.3 279.8,97.5 280.6,97.5 280.6,97.6 281.4,97.6 281.4,97.3 282.2,97.3 282.2,97.6 283.0,97.6 283.0,97.7 283.8,97.7 283.8,97.5 284.6,97.5 284.6,97.2 285.4,97.2 285.4,97.3 286.2,97.3 286.2,97.2 287.0,97.2 287.0,97.4 287.8,97.4 287.8,98.2 288.6,98.2 288.6,97.5 289.4,97.5 289.4,97.3 290.2,97.3 290.2,98.5 291.0,98.5 291.0,98.0 291.8,98.0 291.8,97.7 292.6,97.7 292.6,97.9 293.4,97.9 293.4,97.8 294.2,97.8 294.2,97.6 294.9,97.6 294.9,97.7 295.7,97.7 295.7,97.8 296.5,97.8 296.5,98.4 297.3,98.4 297.3,97.5 298.1,97.5 298.1,98.2 298.9,98.2 298.9,98.2 299.7,98.2 299.7,97.8 300.5,97.8 300.5,97.3 301.3,97.3 301.3,97.8 302.1,97.8 302.1,97.6 302.9,97.6 302.9,97.8 303.7,97.8 303.7,97.9 304.5,97.9 304.5,97.8 305.3,97.8 305.3,97.4 306.1,97.4 306.1,97.2 306.9,97.2 306.9,98.0 307.7,98.0 307.7,98.3 308.5,98.3 308.5,97.9 309.3,97.9 309.3,98.1 310.1,98.1 310.1,97.7 310.9,97.7 310.9,98.0 311.7,98.0 311.7,97.9 312.5,97.9 312.5,97.7 313.3,97.7 313.3,97.6 314.1,97.6 314.1,97.9 314.9,97.9 314.9,98.0 315.7,98.0 315.7,98.0 316.5,98.0 316.5,97.5 317.3,97.5 317.3,97.9 318.1,97.9 318.1,98.6 318.8,98.6 318.8,97.7 319.6,97.7 319.6,97.5 320.4,97.5 320.4,97.5 321.2,97.5 321.2,98.1 322.0,98.1 322.0,98.2 322.8,98.2 322.8,98.3 323.6,98.3 323.6,98.3 324.4,98.3 324.4,98.3 325.2,98.3 325.2,97.8 326.0,97.8 326.0,97.7 326.8,97.7 326.8,98.4 327.6,98.4 327.6,97.9 328.4,97.9 328.4,98.0 329.2,98.0 329.2,98.2 330.0,98.2 330.0,97.1"/>
<circle class="nj-charts-json-dot" cx="231.2" cy="153.7" r="3.5"><title>#5328: 2.2&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="231.2" y1="54.0" x2="231.2" y2="148.7"/>
<circle class="nj-theme-dot" cx="231.2" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="231.2" y="50.0" text-anchor="middle">4</text>
<circle class="nj-charts-json-dot" cx="265.5" cy="123.4" r="3.5"><title>#5824: 3.5&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="265.5" y1="54.0" x2="265.5" y2="118.4"/>
<circle class="nj-theme-dot" cx="265.5" cy="46.0" r="7.5"/>
<text class="nj-theme-num" x="265.5" y="50.0" text-anchor="middle">6</text>
<circle class="nj-charts-json-dot" cx="277.4" cy="96.9" r="3.5"><title>#5885: 5.1&#215;</title></circle>
<line class="nj-charts-grid" stroke-dasharray="2 2" x1="277.4" y1="36.0" x2="277.4" y2="91.9"/>
<circle class="nj-theme-dot" cx="277.4" cy="28.0" r="7.5"/>
<text class="nj-theme-num" x="277.4" y="32.0" text-anchor="middle">6</text>
<line class="nj-charts-axis" x1="44" y1="208" x2="330" y2="208"/>
<text class="nj-charts-note" x="8" y="262">speedup over 3.12.0 (log scale), more is better</text>
</svg>

</div>
</div>

<p class="nj-caption" markdown>Speedup over 3.12.0 after each commit that changed the headers, for the four workloads
not shown in the timeline section. More is better; the badges are theme numbers.</p>

The parse panels include destroying the result: the benchmark returns `json::parse(text).size()`, so the changes to the
destructor ([#5762][5762], [#5835][5835]) show up there too, as steps of up to 6% in either direction. When `accept()`
of `twitter.json` got 2.5% slower over the last 20 commits, we timed the two ends against each other in one binary with
six code layouts: they were equal within 0.2%.

| workload | theme | pull request | change | step |
| --- | :-: | --- | --- | --: |
| `parse()` `citm_catalog.json` | <span class="nj-theme">4</span> | [#5234][5234] | the token buffer is filled only for error messages | −35% |
| | <span class="nj-theme">1</span> | [#5283][5283] | fast paths for contiguous input | −19% |
| | <span class="nj-theme">4</span> | [#5592][5592] | check for the expected `:` or `,` before the lexer's token switch | −7% |
| | <span class="nj-theme">4</span> | [#5809][5809] | positions derived only on error | −12% |
| | <span class="nj-theme">2</span> | [#5810][5810] | indentation skipped eight bytes at a time | −12% |
| | <span class="nj-theme">4</span> | [#5882][5882] | arrays allocated once, at their final size | −6% |
| | <span class="nj-theme">1</span> | [#6031][6031] | one loop for parser and lexer on contiguous input | −12% |
| `parse()` `canada.json` | <span class="nj-theme">4</span> | [#5234][5234] | the token buffer is filled only for error messages | −10% |
| | <span class="nj-theme">1</span> | [#5283][5283] | fast paths for contiguous input | −24% |
| | <span class="nj-theme">3</span> | [#5617][5617] | Eisel-Lemire instead of `strtod` | −9% |
| | <span class="nj-theme">3</span> | [#5738][5738] | own float parser, string scan, `\u` table | −14% |
| | <span class="nj-theme">3</span> | [#5851][5851] | digits accumulated while validating, eight at a time | −12% |
| | <span class="nj-theme">4</span> | [#5882][5882] | arrays allocated once, at their final size | −15% |
| | <span class="nj-theme">1</span> | [#6031][6031] | one loop for parser and lexer on contiguous input | −16% |
| `accept()` `twitter.json` | <span class="nj-theme">4</span> | [#5234][5234] | the token buffer is filled only for error messages | −18% |
| | <span class="nj-theme">1</span> | [#5283][5283] | fast paths for contiguous input | −53% |
| | <span class="nj-theme">4</span> | [#5592][5592] | check for the expected `:` or `,` before the lexer's token switch | −11% |
| | <span class="nj-theme">4</span> | [#5809][5809] | positions derived only on error | −23% |
| | <span class="nj-theme">2</span> | [#5810][5810] | indentation skipped eight bytes at a time | −9% |
| | <span class="nj-theme">2</span> | [#5853][5853] | strings scanned 16 bytes at a time with SSE2 or NEON | −11% |
| | <span class="nj-theme">1</span> | [#6031][6031] | one loop for parser and lexer on contiguous input | −51% |
| `parse()` `twitter.json`, `std::ifstream` | <span class="nj-theme">1</span> | [#5828][5828] | scanning the stream's get area in bulk | −48% |
| | <span class="nj-theme">1</span> | [#5884][5884] | inline get-area path, binary reads | −5% |
| `dump()` `twitter.json` | <span class="nj-theme">6</span> | [#5285][5285] | a write buffer and bulk copies of strings | −70% |
| | <span class="nj-theme">2</span> | [#5738][5738] | own float parser, string scan, `\u` table | −19% |
| | <span class="nj-theme">2</span> | [#5878][5878] | short strings checked with a table | −6% |
| | <span class="nj-theme">2</span> | [#5883][5883] | strings of 16–32 bytes as two overlapping vectors | −34% |
| `dump()` `canada.json` | <span class="nj-theme">6</span> | [#5285][5285] | a write buffer and bulk copies of strings | −8% |
| | <span class="nj-theme">3</span> | [#5634][5634] | Żmij instead of Grisu2 | −65% |
| `from_cbor()` `twitter.json` | <span class="nj-theme">1</span> | [#5233][5233] | binary strings read in bulk | −32% |
| | <span class="nj-theme">4</span> | [#5501][5501] | the result moved instead of copied | −33% |
| | <span class="nj-theme nj-theme--other">U</span> | [#5185][5185], [#5531][5531] | UTF-8 validation of every text string | +37% |
| | <span class="nj-theme nj-theme--other">U</span> | [#5746][5746] | the validation made an option ([#5741][5741]) | −27% |
| | <span class="nj-theme">4</span> | [#6028][6028] | binary strings appended without filling them with zeros first | −6% |
| `to_cbor()` `twitter.json` | <span class="nj-theme">4</span> | [#5328][5328] | no temporary `basic_json` per object key (by [@alexprabhat99](https://github.com/alexprabhat99)) | −55% |
| | <span class="nj-theme">6</span> | [#5824][5824] | a cursor instead of `vector::insert()` | −38% |
| | <span class="nj-theme">6</span> | [#5885][5885] | runs of numbers encoded in a loop | −32% |

<p class="nj-table-caption" markdown>The labeled steps of the timeline: the change in time at the first commit of each
pull request, against the commit before it; for [#6031][6031], which was not merged yet, the step to 3.13.0.
[#5592][5592] is by [@mvanslobbe](https://github.com/mvanslobbe).</p>

### D. Algorithmic fixes

| operation | 3.12.0 | 3.13.0 | speedup | cause | PR |
| --- | --: | --: | --: | --- | --- |
| `diff()` of an array of 64,000 numbers against an empty array | 4,237 ms | 10.8 ms | 394× | each `remove` was inserted at the front of the patch | [#5461][5461] |
| `diff()` of an array of 20,000 objects against every second one of them | 122 ms | 4.13 ms | 29× | the same | [#5461][5461] |
| `parse()` with a callback that rejects half of 32,000 objects | 1,398 ms | 12.1 ms | 116× | each rejected value was searched for from the start of its parent | [#5457][5457] |
| `<` on two equal values nested 24 levels deep (C++11 to C++17) | 64.4 ms | 0.002 ms | exponential | `std::vector`'s `<` asks `a < b` and `b < a`, and both recurse | [#5390][5390] |
| `<` on `citm_catalog.json` and a copy, 10× (C++11 to C++17) | 284 ms | 3.94 ms | 72× | the same | [#5390][5390] |
| `flatten()` of `citm_catalog.json` as `ordered_json` | 271 ms | 1.45 ms | 187× | every new key was looked up linearly | [#5834][5834] |
| `to_bson()` of a value nested 200 levels deep, 100× | 20.3 ms | 0.352 ms | 58× | each document's size was computed by walking everything below it again | [#5553][5553], [#5979][5979] |
| 100,000 × `push_back()` on an `ordered_json` with [`JSON_DIAGNOSTICS`](../../api/macros/json_diagnostics.md) | 1,589 ms | 5.32 ms | 299× | every insert re-pointed the parent pointers of all elements | [#5832][5832] |
| 10,000 × `at(i)` on an `ordered_json` array with `JSON_DIAGNOSTICS` | 45.9 ms | 0.088 ms | 522× | the same | [#5832][5832] |

<p class="nj-table-caption" markdown>Operations that were quadratic or worse in 3.12.0, timed with both versions (C++17,
`-O3`, median of 3 interleaved runs).</p>

### E. Comparison with other libraries

**Method.** The programs are in
[`tests/benchmarks/json_view/others`](https://github.com/nlohmann/json/tree/develop/tests/benchmarks/json_view/others),
whose README lists every variant, the pinned versions and checksums of every library, and the build commands. The
libraries: [yyjson](https://github.com/ibireme/yyjson) 0.13.0, [simdjson](https://github.com/simdjson/simdjson) 5.1.1,
[sonic-cpp](https://github.com/bytedance/sonic-cpp) 1.0.2, [RapidJSON](https://github.com/Tencent/rapidjson) (master,
24b5e7a, as its last release is from 2016), [Glaze](https://github.com/stephenberry/glaze) 9.1.0,
[Boost.JSON](https://github.com/boostorg/json) 1.92, and in Rust [sonic-rs](https://github.com/cloudwego/sonic-rs)
0.5.10, [simd-json](https://github.com/simd-lite/simd-json) 0.19.0 and [serde_json](https://github.com/serde-rs/json)
1.0.154. C++23 with `-O3`; on the Mac Apple clang 21 (the compiler of the current Xcode), on x86-64 GCC 16.2, GCC 13.4
and Clang 23 with `-march=haswell` on Ubuntu 26.04, pinned to one core; Rust 1.99 with `-C target-cpu=haswell` on
x86-64. The Rust times on the Mac are from October 29; the Rust programs haven't changed since. Every variant runs in
every round, in a different order each round (a shuffle with a fixed seed), each timed call after an untimed one; the
time is the best of 2 × 30 rounds (2 × 6 for `jeopardy.json`). Boost.JSON uses a monotonic resource and precise number
parsing, RapidJSON `kParseFullPrecisionFlag` (except in *validate*, which reads no number), serde_json
`float_roundtrip`: every number a library converts has to be exact. That rule, like the others here, is our choice.
Between the two runs, a C++ library's time relative to `json_document`'s moved by 0.6% at the median and 2.4% at the
95th percentile on the Mac, and by 1.7–2.0% and 7–8% on x86-64 (the Rust programs were not run again).

**Validation levels.** A way validates fully if it rejects all four broken inputs (cut short by one byte, a stray comma,
an invalid UTF-8 byte in a string, garbage after the value); "U" accepts the invalid UTF-8 byte; "P" accepts one of the
other three. The probes separate the ways that check everything from those that check less; JSONTestSuite is the
conformance check. sonic-cpp 1.0.2 does not check UTF-8. RapidJSON does only with `kParseValidateEncodingFlag`, and
serde_json reading into `IgnoredAny` or structs from bytes doesn't check the strings it skips, unless the input is
checked with `std::str::from_utf8` first; both are shown both ways. simdjson's On-Demand API, Glaze's `lazy_json`,
`simdjson::minify()` and Glaze's `minify_json()` don't validate what they skip, Glaze's structs only with
`validate_skipped`, and Glaze's generic reader rejects garbage after the value only with `validate_trailing_whitespace`
(its strict variants also set `escape_control_characters`, without which it writes control characters unescaped).

**Conformance.** Every *validate* way ran the 318 files of [JSONTestSuite](https://github.com/nst/JSONTestSuite), on the
Mac with the headers of November 3 and on x86-64 with those of October 30 (the Mac's results didn't change). No way
rejected a file that must be accepted. Of those that must be rejected, a few got through: `123` followed by a NUL byte
in nlohmann/json and RapidJSON (nlohmann/json treats NUL as the end of the input;
[`JSON_STRICT_NUL_HANDLING`](../../api/macros/json_strict_nul_handling.md) changes that for `json` and `json_document`),
an incomplete UTF-8 byte-order mark in RapidJSON, an invalid `\u` escape in sonic-rs's `IgnoredAny`, and, in 17 files,
garbage after the value in Glaze's generic reader without `validate_trailing_whitespace`. sonic-rs, and RapidJSON's SAX
reader with GCC 16.2 on x86-64, crash with a stack overflow on 100,000 nested arrays. Neither machine has AVX-512, so
simdjson's fastest kernel never ran, and yyjson and simdjson are compiled as separate files without link-time
optimization, while the header-only libraries inline into the benchmark. Built with link-time optimization, and simdjson
as C++23 like the rest, they moved by less than 3% against `json_document` on average (Apple clang and GCC 16).

**Choices.** A library's time is its fastest fully validating way per file; "(U …)", "(P …)" and "(N …)" give a faster
way that checks or does less. A cell of the figures is the geometric mean of a library's four times, divided by the
smallest such mean in its column. Variants that keep a parser or document across calls are measured but not chosen, and
so are in-place ways with the copy made before the timer starts; with every library reused, the first place in each
column stays the same. Variants that leave numbers unconverted while reading are chosen where they pass the checks
(yyjson's and RapidJSON's raw numbers, Boost.JSON's `number_precision::none`). Variants that write each number by
copying its text instead of formatting it (`json_document` with `number_format::source`, yyjson's and RapidJSON's raw
numbers) count as doing less, "N": their output keeps the source's spelling of each number. They matter most for
`canada.json`. Glaze's `generic` with `double` numbers fails the checks wherever it has to write the 64-bit ids of
`twitter.json`. The struct variants of nlohmann/json, Glaze, simdjson, and serde read into the same types; Boost.JSON's
`parse_into` has no type that skips a value, so it holds a little more.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog nj-charts--heat" viewBox="0 0 784 510" role="img" aria-labelledby="nj-blog-uc-x86-clang nj-blog-uc-x86-clang-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-uc-x86-clang">Use cases: time of each library relative to the fastest, x86-64 with Clang 23</title>
<desc id="nj-blog-uc-x86-clang-d">Table of relative times, libraries by use case. nlohmann/json json_document validate: 1.00; nlohmann/json json_document sum: 1.05; nlohmann/json json_document select: 1.00; nlohmann/json json_document edit: 1.00 (0.81 doing less, N); nlohmann/json json_document minify: 1.00 (0.83 doing less, N); nlohmann/json json_document write: 1.00 (0.71 doing less, N); yyjson validate: 2.21; yyjson sum: 1.23; yyjson select: 1.40; yyjson edit: 1.48; yyjson minify: 1.27 (1.09 doing less, N); yyjson write: 1.16; sonic-cpp validate: no fully validating way (2.32 doing less, U); sonic-cpp sum: no fully validating way (1.26 doing less, U); sonic-cpp select: no fully validating way (1.50 doing less, U); sonic-cpp edit: no fully validating way (1.21 doing less, U); sonic-cpp minify: no fully validating way (1.36 doing less, U); sonic-cpp write: 1.33; simdjson validate: 2.06; simdjson sum: 1.19; simdjson select: 1.33 (0.56 doing less, P); simdjson edit: n/a; simdjson minify: 1.55 (0.18 doing less, P); simdjson write: 2.07; sonic-rs (Rust) validate: 1.90; sonic-rs (Rust) sum: 1.13; sonic-rs (Rust) select: 1.37; sonic-rs (Rust) edit: 1.90; sonic-rs (Rust) minify: 1.75; sonic-rs (Rust) write: 2.01; Boost.J&#8203;SON validate: 1.80; Boost.J&#8203;SON sum: 1.17; Boost.J&#8203;SON select: 2.19; Boost.J&#8203;SON edit: 2.37; Boost.J&#8203;SON minify: 2.65; Boost.J&#8203;SON write: 2.38; nlohmann/json json validate: 1.43; nlohmann/json json sum: 1.00; nlohmann/json json select: 6.54; nlohmann/json json edit: 3.53; nlohmann/json json minify: 4.31; nlohmann/json json write: 1.88; simd-json (Rust) validate: 3.57; simd-json (Rust) sum: 1.91; simd-json (Rust) select: 2.61; simd-json (Rust) edit: 2.88; simd-json (Rust) minify: 3.43; simd-json (Rust) write: 2.28; serde_json (Rust) validate: 2.36 (2.11 doing less, U); serde_json (Rust) sum: 2.35; serde_json (Rust) select: 1.75; serde_json (Rust) edit: 4.53; serde_json (Rust) minify: 4.99; serde_json (Rust) write: 2.22; Glaze validate: 2.24; Glaze sum: 4.24 (3.96 doing less, P); Glaze select: 1.39 (0.61 doing less, P); Glaze edit: 5.50; Glaze minify: 5.78 (0.69 doing less, P); Glaze write: 1.95; RapidJSON validate: 5.18 (3.77 doing less, U); RapidJSON sum: 3.25 (2.40 doing less, U); RapidJSON select: 4.45 (3.45 doing less, U); RapidJSON edit: 3.16 (2.68 doing less, U); RapidJSON minify: 3.43 (2.57 doing less, U N); RapidJSON write: 2.86.</desc>
<text class="nj-charts-tick" x="270" y="34">validate</text>
<text class="nj-charts-tick" x="362" y="34">sum</text>
<text class="nj-charts-tick" x="454" y="34">select</text>
<text class="nj-charts-tick" x="546" y="34">edit</text>
<text class="nj-charts-tick" x="638" y="34">minify</text>
<text class="nj-charts-tick" x="730" y="34">write</text>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="66" text-anchor="end">nlohmann/json json_document</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · validate&#10;1.00× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 250 µs&#10;citm_catalog.json: 509 µs&#10;canada.json: 1,032 µs&#10;jeopardy.json: 34,454 µs">
<rect class="nj-heat-0" x="225" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · sum&#10;1.05× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 366 µs&#10;citm_catalog.json: 941 µs&#10;canada.json: 3,680 µs&#10;jeopardy.json: 86,966 µs">
<rect class="nj-heat-0" x="317" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="66" text-anchor="middle">1.05</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · select&#10;1.00× the time of the fastest library (fully validating)&#10;twitter.json: 316 µs · structs (from_json)&#10;citm_catalog.json: 783 µs · parse&#10;canada.json: 1,368 µs · structs (from_json)&#10;jeopardy.json: 91,736 µs · parse">
<rect class="nj-heat-0" x="409" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit&#10;1.00× the time of the fastest library (fully validating)&#10;way: editable&#10;twitter.json: 519 µs&#10;citm_catalog.json: 1,152 µs&#10;canada.json: 5,671 µs&#10;jeopardy.json: 195,716 µs">
<rect class="nj-heat-0" x="501" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit, checking less&#10;0.81× the time of the fastest fully validating library&#10;twitter.json: 518 µs · editable (source numbers) (validates fully)&#10;citm_catalog.json: 1,152 µs · editable (validates fully)&#10;canada.json: 2,502 µs · editable (source numbers) (validates fully)&#10;jeopardy.json: 195,716 µs · editable (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="547" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="60" text-anchor="middle">0.81</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 472 µs&#10;citm_catalog.json: 1,055 µs&#10;canada.json: 5,041 µs&#10;jeopardy.json: 149,143 µs">
<rect class="nj-heat-0" x="593" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify, checking less&#10;0.83× the time of the fastest fully validating library&#10;twitter.json: 467 µs · parse + dump (source numbers) (validates fully)&#10;citm_catalog.json: 1,055 µs · parse + dump (validates fully)&#10;canada.json: 2,363 µs · parse + dump (source numbers) (validates fully)&#10;jeopardy.json: 149,143 µs · parse + dump (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="639" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="60" text-anchor="middle">0.83</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write&#10;1.00× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 158 µs&#10;citm_catalog.json: 279 µs&#10;canada.json: 3,637 µs&#10;jeopardy.json: 67,366 µs">
<rect class="nj-heat-0" x="685" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="707.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write, checking less&#10;0.71× the time of the fastest fully validating library&#10;twitter.json: 153 µs · dump (source numbers) (validates fully)&#10;citm_catalog.json: 276 µs · dump (source numbers) (validates fully)&#10;canada.json: 982 µs · dump (source numbers) (validates fully)&#10;jeopardy.json: 67,366 µs · dump (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="731" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="752.5" y="60" text-anchor="middle">0.71</text>
<text class="nj-charts-cell nj-charts-cell--small" x="752.5" y="73" text-anchor="middle">N</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="102" text-anchor="end">yyjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · validate&#10;2.21× the time of the fastest library (fully validating)&#10;twitter.json: 383 µs · read&#10;citm_catalog.json: 887 µs · read&#10;canada.json: 2,572 µs · read (raw numbers)&#10;jeopardy.json: 123,640 µs · read (raw numbers)">
<rect class="nj-heat-2" x="225" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="102" text-anchor="middle">2.21</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · sum&#10;1.23× the time of the fastest library (fully validating)&#10;twitter.json: 436 µs · read&#10;citm_catalog.json: 1,048 µs · insitu (copy)&#10;canada.json: 3,454 µs · read&#10;jeopardy.json: 133,577 µs · read&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="317" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="102" text-anchor="middle">1.23</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · select&#10;1.40× the time of the fastest library (fully validating)&#10;twitter.json: 386 µs · insitu (copy)&#10;citm_catalog.json: 891 µs · insitu (copy)&#10;canada.json: 2,572 µs · read (raw numbers)&#10;jeopardy.json: 135,813 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="409" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="102" text-anchor="middle">1.40</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · edit&#10;1.48× the time of the fastest library (fully validating)&#10;twitter.json: 833 µs · mut copy&#10;citm_catalog.json: 1,674 µs · mut copy&#10;canada.json: 7,249 µs · mut copy&#10;jeopardy.json: 316,652 µs · insitu (copy) + mut copy&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="501" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="102" text-anchor="middle">1.48</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify&#10;1.27× the time of the fastest library (fully validating)&#10;way: read + write&#10;twitter.json: 626 µs&#10;citm_catalog.json: 1,261 µs&#10;canada.json: 6,179 µs&#10;jeopardy.json: 200,886 µs">
<rect class="nj-heat-1" x="593" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="102" text-anchor="middle">1.27</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify, checking less&#10;1.09× the time of the fastest fully validating library&#10;twitter.json: 626 µs · read + write (validates fully)&#10;citm_catalog.json: 1,236 µs · read (raw numbers) + write (validates fully)&#10;canada.json: 3,426 µs · read (raw numbers) + write (validates fully)&#10;jeopardy.json: 197,700 µs · read (raw numbers) + write (validates fully)&#10;copies each number&#x27;s text instead of formatting it (YYJSON_READ_NUMBER_AS_RAW)">
<rect class="nj-heat-0" x="639" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="96" text-anchor="middle">1.09</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="109" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · write&#10;1.16× the time of the fastest library (fully validating)&#10;way: write&#10;twitter.json: 216 µs&#10;citm_catalog.json: 367 µs&#10;canada.json: 3,366 µs&#10;jeopardy.json: 73,272 µs">
<rect class="nj-heat-1" x="685" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="102" text-anchor="middle">1.16</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="138" text-anchor="end">sonic-cpp</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · validate, checking less&#10;2.32× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 451 µs&#10;citm_catalog.json: 998 µs&#10;canada.json: 3,031 µs&#10;jeopardy.json: 95,823 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="225" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="132" text-anchor="middle">2.32</text>
<text class="nj-charts-cell nj-charts-cell--small" x="270" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · sum, checking less&#10;1.26× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 504 µs&#10;citm_catalog.json: 1,176 µs&#10;canada.json: 3,701 µs&#10;jeopardy.json: 104,509 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="317" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="132" text-anchor="middle">1.26</text>
<text class="nj-charts-cell nj-charts-cell--small" x="362" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · select, checking less&#10;1.50× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 454 µs&#10;citm_catalog.json: 1,015 µs&#10;canada.json: 3,025 µs&#10;jeopardy.json: 112,621 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="409" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="132" text-anchor="middle">1.50</text>
<text class="nj-charts-cell nj-charts-cell--small" x="454" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · edit, checking less&#10;1.21× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 642 µs&#10;citm_catalog.json: 1,497 µs&#10;canada.json: 8,153 µs&#10;jeopardy.json: 184,321 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="501" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="132" text-anchor="middle">1.21</text>
<text class="nj-charts-cell nj-charts-cell--small" x="546" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · minify, checking less&#10;1.36× the time of the fastest fully validating library&#10;way: Document + Serialize&#10;twitter.json: 655 µs&#10;citm_catalog.json: 1,474 µs&#10;canada.json: 7,856 µs&#10;jeopardy.json: 169,992 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="593" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="132" text-anchor="middle">1.36</text>
<text class="nj-charts-cell nj-charts-cell--small" x="638" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · write&#10;1.33× the time of the fastest library (fully validating)&#10;way: Serialize&#10;twitter.json: 228 µs&#10;citm_catalog.json: 474 µs&#10;canada.json: 4,766 µs&#10;jeopardy.json: 66,619 µs">
<rect class="nj-heat-1" x="685" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="138" text-anchor="middle">1.33</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="174" text-anchor="end">simdjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · validate&#10;2.06× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 302 µs&#10;citm_catalog.json: 721 µs&#10;canada.json: 3,202 µs&#10;jeopardy.json: 116,859 µs">
<rect class="nj-heat-2" x="225" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="174" text-anchor="middle">2.06</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · sum&#10;1.19× the time of the fastest library (fully validating)&#10;twitter.json: 391 µs · D&#8203;OM&#10;citm_catalog.json: 969 µs · D&#8203;OM&#10;canada.json: 4,121 µs · D&#8203;OM&#10;jeopardy.json: 116,855 µs · On-Demand">
<rect class="nj-heat-1" x="317" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="174" text-anchor="middle">1.19</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select&#10;1.33× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 318 µs&#10;citm_catalog.json: 728 µs&#10;canada.json: 3,213 µs&#10;jeopardy.json: 129,986 µs">
<rect class="nj-heat-1" x="409" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="174" text-anchor="middle">1.33</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select, checking less&#10;0.56× the time of the fastest fully validating library&#10;way: On-Demand&#10;twitter.json: 182 µs&#10;citm_catalog.json: 494 µs&#10;canada.json: 692 µs&#10;jeopardy.json: 50,660 µs&#10;reads lazily: On-Demand reads only what you ask for and steps over the rest by matching brackets">
<rect class="nj-heat-0" x="455" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="168" text-anchor="middle">0.56</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · edit&#10;simdjson&#x27;s documents are read-only: it has no A&#8203;PI to change a value and write the result">
<rect class="nj-heat-na" x="501" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-tick" x="546" y="174">n/a</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify&#10;1.55× the time of the fastest library (fully validating)&#10;way: D&#8203;OM + to_string&#10;twitter.json: 706 µs&#10;citm_catalog.json: 1,411 µs&#10;canada.json: 8,125 µs&#10;jeopardy.json: 270,332 µs">
<rect class="nj-heat-2" x="593" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="174" text-anchor="middle">1.55</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify, checking less&#10;0.18× the time of the fastest fully validating library&#10;way: minify&#10;twitter.json: 99.0 µs&#10;citm_catalog.json: 270 µs&#10;canada.json: 329 µs&#10;jeopardy.json: 42,546 µs&#10;simdjson::minify() only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="168" text-anchor="middle">0.18</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · write&#10;2.07× the time of the fastest library (fully validating)&#10;way: to_string&#10;twitter.json: 382 µs&#10;citm_catalog.json: 661 µs&#10;canada.json: 4,787 µs&#10;jeopardy.json: 162,220 µs">
<rect class="nj-heat-2" x="685" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="174" text-anchor="middle">2.07</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="210" text-anchor="end">sonic-rs (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · validate&#10;1.90× the time of the fastest library (fully validating)&#10;way: IgnoredAny&#10;twitter.json: 501 µs&#10;citm_catalog.json: 970 µs&#10;canada.json: 2,249 µs&#10;jeopardy.json: 54,369 µs">
<rect class="nj-heat-2" x="225" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="210" text-anchor="middle">1.90</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · sum&#10;1.13× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 501 µs&#10;citm_catalog.json: 1,123 µs&#10;canada.json: 4,397 µs&#10;jeopardy.json: 59,583 µs">
<rect class="nj-heat-0" x="317" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="210" text-anchor="middle">1.13</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · select&#10;1.37× the time of the fastest library (fully validating)&#10;way: structs&#10;twitter.json: 504 µs&#10;citm_catalog.json: 1,033 µs&#10;canada.json: 2,328 µs&#10;jeopardy.json: 90,486 µs">
<rect class="nj-heat-1" x="409" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="210" text-anchor="middle">1.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · edit&#10;1.90× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,197 µs&#10;citm_catalog.json: 2,389 µs&#10;canada.json: 7,744 µs&#10;jeopardy.json: 390,952 µs">
<rect class="nj-heat-2" x="501" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="210" text-anchor="middle">1.90</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · minify&#10;1.75× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,000 µs&#10;citm_catalog.json: 2,097 µs&#10;canada.json: 7,795 µs&#10;jeopardy.json: 215,280 µs">
<rect class="nj-heat-2" x="593" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="210" text-anchor="middle">1.75</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · write&#10;2.01× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 434 µs&#10;citm_catalog.json: 927 µs&#10;canada.json: 3,987 µs&#10;jeopardy.json: 109,176 µs">
<rect class="nj-heat-2" x="685" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="210" text-anchor="middle">2.01</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="246" text-anchor="end">Boost.J&#8203;SON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · validate&#10;1.80× the time of the fastest library (fully validating)&#10;twitter.json: 570 µs · S&#8203;AX (numbers: none)&#10;citm_catalog.json: 903 µs · S&#8203;AX (numbers: none)&#10;canada.json: 1,678 µs · S&#8203;AX (numbers: none)&#10;jeopardy.json: 55,087 µs · S&#8203;AX">
<rect class="nj-heat-2" x="225" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="246" text-anchor="middle">1.80</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · sum&#10;1.17× the time of the fastest library (fully validating)&#10;way: S&#8203;AX&#10;twitter.json: 580 µs&#10;citm_catalog.json: 928 µs&#10;canada.json: 5,715 µs&#10;jeopardy.json: 55,874 µs">
<rect class="nj-heat-1" x="317" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="246" text-anchor="middle">1.17</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · select&#10;2.19× the time of the fastest library (fully validating)&#10;twitter.json: 760 µs · parse_into structs&#10;citm_catalog.json: 1,388 µs · parse_into structs&#10;canada.json: 7,026 µs · parse&#10;jeopardy.json: 97,008 µs · parse_into structs">
<rect class="nj-heat-2" x="409" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="246" text-anchor="middle">2.19</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · edit&#10;2.37× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 1,716 µs&#10;citm_catalog.json: 2,578 µs&#10;canada.json: 13,427 µs&#10;jeopardy.json: 354,510 µs">
<rect class="nj-heat-2" x="501" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="246" text-anchor="middle">2.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · minify&#10;2.65× the time of the fastest library (fully validating)&#10;way: parse + serialize&#10;twitter.json: 1,722 µs&#10;citm_catalog.json: 2,573 µs&#10;canada.json: 12,678 µs&#10;jeopardy.json: 330,878 µs">
<rect class="nj-heat-3" x="593" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="246" text-anchor="middle">2.65</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · write&#10;2.38× the time of the fastest library (fully validating)&#10;way: serialize&#10;twitter.json: 478 µs&#10;citm_catalog.json: 913 µs&#10;canada.json: 5,610 µs&#10;jeopardy.json: 141,994 µs">
<rect class="nj-heat-2" x="685" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="246" text-anchor="middle">2.38</text>
</g>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="282" text-anchor="end">nlohmann/json json</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · validate&#10;1.43× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 335 µs&#10;citm_catalog.json: 711 µs&#10;canada.json: 2,018 µs&#10;jeopardy.json: 39,513 µs">
<rect class="nj-heat-1" x="225" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="282" text-anchor="middle">1.43</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · sum&#10;1.00× the time of the fastest library (fully validating)&#10;way: sax&#10;twitter.json: 431 µs&#10;citm_catalog.json: 914 µs&#10;canada.json: 3,824 µs&#10;jeopardy.json: 60,439 µs">
<rect class="nj-heat-0" x="317" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="282" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · select&#10;6.54× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 3,181 µs&#10;citm_catalog.json: 4,583 µs&#10;canada.json: 9,599 µs&#10;jeopardy.json: 405,734 µs">
<rect class="nj-heat-4" x="409" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="282" text-anchor="middle">6.54</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · edit&#10;3.53× the time of the fastest library (fully validating)&#10;twitter.json: 2,452 µs · ordered_json&#10;citm_catalog.json: 4,402 µs · ordered_json&#10;canada.json: 14,765 µs · parse&#10;jeopardy.json: 646,489 µs · ordered_json">
<rect class="nj-heat-3" x="501" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="282" text-anchor="middle">3.53</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · minify&#10;4.31× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 3,525 µs&#10;citm_catalog.json: 5,178 µs&#10;canada.json: 14,024 µs&#10;jeopardy.json: 506,705 µs">
<rect class="nj-heat-3" x="593" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="282" text-anchor="middle">4.31</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · write&#10;1.88× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 438 µs&#10;citm_catalog.json: 599 µs&#10;canada.json: 4,458 µs&#10;jeopardy.json: 116,318 µs">
<rect class="nj-heat-2" x="685" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="282" text-anchor="middle">1.88</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="318" text-anchor="end">simd-json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · validate&#10;3.57× the time of the fastest library (fully validating)&#10;way: tape (copy)&#10;twitter.json: 567 µs&#10;citm_catalog.json: 1,430 µs&#10;canada.json: 4,359 µs&#10;jeopardy.json: 207,551 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="318" text-anchor="middle">3.57</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · sum&#10;1.91× the time of the fastest library (fully validating)&#10;way: visitor (copy)&#10;twitter.json: 681 µs&#10;citm_catalog.json: 1,650 µs&#10;canada.json: 5,083 µs&#10;jeopardy.json: 210,185 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="317" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="318" text-anchor="middle">1.91</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · select&#10;2.61× the time of the fastest library (fully validating)&#10;way: structs (copy)&#10;twitter.json: 679 µs&#10;citm_catalog.json: 1,731 µs&#10;canada.json: 5,144 µs&#10;jeopardy.json: 239,164 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="318" text-anchor="middle">2.61</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · edit&#10;2.88× the time of the fastest library (fully validating)&#10;twitter.json: 1,862 µs · borrowed (copy)&#10;citm_catalog.json: 4,194 µs · borrowed (copy)&#10;canada.json: 14,896 µs · owned (copy)&#10;jeopardy.json: 391,369 µs · borrowed (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="318" text-anchor="middle">2.88</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · minify&#10;3.43× the time of the fastest library (fully validating)&#10;way: borrowed (copy)&#10;twitter.json: 1,889 µs&#10;citm_catalog.json: 4,196 µs&#10;canada.json: 15,716 µs&#10;jeopardy.json: 414,377 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="593" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="318" text-anchor="middle">3.43</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · write&#10;2.28× the time of the fastest library (fully validating)&#10;way: borrowed&#10;twitter.json: 582 µs&#10;citm_catalog.json: 800 µs&#10;canada.json: 5,147 µs&#10;jeopardy.json: 122,623 µs">
<rect class="nj-heat-2" x="685" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="318" text-anchor="middle">2.28</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="354" text-anchor="end">serde_json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate&#10;2.36× the time of the fastest library (fully validating)&#10;way: from_utf8 + IgnoredAny&#10;twitter.json: 624 µs&#10;citm_catalog.json: 1,440 µs&#10;canada.json: 2,406 µs&#10;jeopardy.json: 64,720 µs">
<rect class="nj-heat-2" x="225" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="354" text-anchor="middle">2.36</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate, checking less&#10;2.11× the time of the fastest fully validating library&#10;way: IgnoredAny&#10;twitter.json: 484 µs&#10;citm_catalog.json: 1,370 µs&#10;canada.json: 2,314 µs&#10;jeopardy.json: 58,247 µs&#10;trusts U&#8203;TF-8 in the strings it skips (from_slice); strings it reads are checked">
<rect class="nj-heat-2" x="271" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="348" text-anchor="middle">2.11</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="361" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · sum&#10;2.35× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 1,311 µs&#10;citm_catalog.json: 2,288 µs&#10;canada.json: 7,127 µs&#10;jeopardy.json: 129,497 µs">
<rect class="nj-heat-2" x="317" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="354" text-anchor="middle">2.35</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · select&#10;1.75× the time of the fastest library (fully validating)&#10;way: from_utf8 + structs&#10;twitter.json: 701 µs&#10;citm_catalog.json: 1,532 µs&#10;canada.json: 2,529 µs&#10;jeopardy.json: 107,316 µs">
<rect class="nj-heat-2" x="409" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="354" text-anchor="middle">1.75</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · edit&#10;4.53× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,042 µs&#10;citm_catalog.json: 6,586 µs&#10;canada.json: 16,631 µs&#10;jeopardy.json: 632,766 µs">
<rect class="nj-heat-3" x="501" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="354" text-anchor="middle">4.53</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · minify&#10;4.99× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,012 µs&#10;citm_catalog.json: 6,583 µs&#10;canada.json: 17,306 µs&#10;jeopardy.json: 509,702 µs">
<rect class="nj-heat-3" x="593" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="354" text-anchor="middle">4.99</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · write&#10;2.22× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 550 µs&#10;citm_catalog.json: 887 µs&#10;canada.json: 4,005 µs&#10;jeopardy.json: 134,163 µs">
<rect class="nj-heat-2" x="685" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="354" text-anchor="middle">2.22</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="390" text-anchor="end">Glaze</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · validate&#10;2.24× the time of the fastest library (fully validating)&#10;way: validate_json&#10;twitter.json: 594 µs&#10;citm_catalog.json: 1,230 µs&#10;canada.json: 2,139 µs&#10;jeopardy.json: 73,235 µs">
<rect class="nj-heat-2" x="225" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="390" text-anchor="middle">2.24</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum&#10;4.24× the time of the fastest library (fully validating)&#10;way: generic (double, strict)&#10;twitter.json: 2,374 µs&#10;citm_catalog.json: 3,982 µs&#10;canada.json: 11,930 µs&#10;jeopardy.json: 261,204 µs">
<rect class="nj-heat-3" x="317" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="390" text-anchor="middle">4.24</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum, checking less&#10;3.96× the time of the fastest fully validating library&#10;twitter.json: 2,374 µs · generic (double, strict) (validates fully)&#10;citm_catalog.json: 3,982 µs · generic (double, strict) (validates fully)&#10;canada.json: 11,921 µs · generic (double)&#10;jeopardy.json: 198,036 µs · lazy_json&#10;accepts trailing garbage after the value: Glaze&#x27;s default (validate_trailing_whitespace checks it)&#10;reads lazily: lazy_json reads only what you ask for and steps over the rest">
<rect class="nj-heat-3" x="363" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="384" text-anchor="middle">3.96</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select&#10;1.39× the time of the fastest library (fully validating)&#10;way: structs (validate_skipped)&#10;twitter.json: 542 µs&#10;citm_catalog.json: 1,369 µs&#10;canada.json: 1,846 µs&#10;jeopardy.json: 83,907 µs">
<rect class="nj-heat-1" x="409" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="390" text-anchor="middle">1.39</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select, checking less&#10;0.61× the time of the fastest fully validating library&#10;way: structs&#10;twitter.json: 337 µs&#10;citm_catalog.json: 416 µs&#10;canada.json: 447 µs&#10;jeopardy.json: 68,455 µs&#10;reads into structs and steps over fields it doesn&#x27;t know without checking them (validate_skipped checks them too)">
<rect class="nj-heat-0" x="455" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="384" text-anchor="middle">0.61</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · edit&#10;5.50× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,896 µs&#10;citm_catalog.json: 7,671 µs&#10;canada.json: 28,104 µs&#10;jeopardy.json: 723,675 µs">
<rect class="nj-heat-4" x="501" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="390" text-anchor="middle">5.50</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify&#10;5.78× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,801 µs&#10;citm_catalog.json: 7,482 µs&#10;canada.json: 26,932 µs&#10;jeopardy.json: 544,342 µs">
<rect class="nj-heat-4" x="593" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="390" text-anchor="middle">5.78</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify, checking less&#10;0.69× the time of the fastest fully validating library&#10;way: minify_json&#10;twitter.json: 422 µs&#10;citm_catalog.json: 1,051 µs&#10;canada.json: 2,140 µs&#10;jeopardy.json: 87,842 µs&#10;minify_json only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="384" text-anchor="middle">0.69</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · write&#10;1.95× the time of the fastest library (fully validating)&#10;twitter.json: 396 µs · generic&#10;citm_catalog.json: 725 µs · generic (strict)&#10;canada.json: 4,107 µs · generic (strict)&#10;jeopardy.json: 132,573 µs · generic">
<rect class="nj-heat-2" x="685" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="390" text-anchor="middle">1.95</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="426" text-anchor="end">RapidJSON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate&#10;5.18× the time of the fastest library (fully validating)&#10;twitter.json: 1,798 µs · insitu (copy)&#10;citm_catalog.json: 1,944 µs · S&#8203;AX (default precision)&#10;canada.json: 4,019 µs · S&#8203;AX (string stream, default precision)&#10;jeopardy.json: 232,684 µs · S&#8203;AX (string stream, default precision)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-4" x="225" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="426" text-anchor="middle">5.18</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate, checking less&#10;3.77× the time of the fastest fully validating library&#10;twitter.json: 1,173 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,504 µs · S&#8203;AX (default precision) (no encoding check)&#10;canada.json: 4,019 µs · S&#8203;AX (string stream, default precision) (validates fully)&#10;jeopardy.json: 128,516 µs · S&#8203;AX (string stream, default precision) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="271" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="420" text-anchor="middle">3.77</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum&#10;3.25× the time of the fastest library (fully validating)&#10;twitter.json: 1,846 µs · insitu (copy)&#10;citm_catalog.json: 2,176 µs · S&#8203;AX&#10;canada.json: 10,561 µs · S&#8203;AX (string stream)&#10;jeopardy.json: 239,499 µs · S&#8203;AX (string stream)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="317" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="426" text-anchor="middle">3.25</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum, checking less&#10;2.40× the time of the fastest fully validating library&#10;twitter.json: 1,229 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,761 µs · S&#8203;AX (no encoding check)&#10;canada.json: 10,561 µs · S&#8203;AX (string stream) (validates fully)&#10;jeopardy.json: 131,510 µs · S&#8203;AX (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="363" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="420" text-anchor="middle">2.40</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select&#10;4.45× the time of the fastest library (fully validating)&#10;way: insitu (copy)&#10;twitter.json: 1,806 µs&#10;citm_catalog.json: 2,303 µs&#10;canada.json: 11,395 µs&#10;jeopardy.json: 257,762 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="426" text-anchor="middle">4.45</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select, checking less&#10;3.45× the time of the fastest fully validating library&#10;twitter.json: 1,184 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,929 µs · insitu (copy) (no encoding check)&#10;canada.json: 11,261 µs · Document (string stream) (no encoding check)&#10;jeopardy.json: 171,716 µs · Document (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="455" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="420" text-anchor="middle">3.45</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit&#10;3.16× the time of the fastest library (fully validating)&#10;way: insitu (copy)&#10;twitter.json: 2,478 µs&#10;citm_catalog.json: 3,261 µs&#10;canada.json: 21,686 µs&#10;jeopardy.json: 378,727 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="426" text-anchor="middle">3.16</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit, checking less&#10;2.68× the time of the fastest fully validating library&#10;twitter.json: 1,842 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 2,887 µs · insitu (copy) (no encoding check)&#10;canada.json: 21,686 µs · insitu (copy) (validates fully)&#10;jeopardy.json: 294,727 µs · Document (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="547" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="420" text-anchor="middle">2.68</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify&#10;3.43× the time of the fastest library (fully validating)&#10;twitter.json: 2,456 µs · S&#8203;AX to Writer&#10;citm_catalog.json: 2,864 µs · S&#8203;AX to Writer&#10;canada.json: 21,753 µs · Document + Writer&#10;jeopardy.json: 338,985 µs · S&#8203;AX to Writer (string stream)">
<rect class="nj-heat-3" x="593" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="426" text-anchor="middle">3.43</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify, checking less&#10;2.57× the time of the fastest fully validating library&#10;twitter.json: 1,794 µs · S&#8203;AX to Writer (no encoding check)&#10;citm_catalog.json: 2,444 µs · S&#8203;AX to Writer (no encoding check)&#10;canada.json: 14,707 µs · S&#8203;AX to Writer (raw numbers) (no encoding check)&#10;jeopardy.json: 252,656 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;copies each number&#x27;s text instead of formatting it (kParseNumbersAsStringsFlag)">
<rect class="nj-heat-3" x="639" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="420" text-anchor="middle">2.57</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="433" text-anchor="middle">U N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · write&#10;2.86× the time of the fastest library (fully validating)&#10;way: Writer&#10;twitter.json: 633 µs&#10;citm_catalog.json: 960 µs&#10;canada.json: 9,388 µs&#10;jeopardy.json: 127,319 µs">
<rect class="nj-heat-3" x="685" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="426" text-anchor="middle">2.86</text>
</g>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="472">time relative to the fastest fully validating library, less is better</text>
<g><rect class="nj-heat-0" x="8" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="46" y="496" text-anchor="middle">below 1.15</text></g>
<g><rect class="nj-heat-1" x="88" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="126" y="496" text-anchor="middle">1.15 to 1.5</text></g>
<g><rect class="nj-heat-2" x="168" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="206" y="496" text-anchor="middle">1.5 to 2.5</text></g>
<g><rect class="nj-heat-3" x="248" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="286" y="496" text-anchor="middle">2.5 to 5</text></g>
<g><rect class="nj-heat-4" x="328" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="366" y="496" text-anchor="middle">5 and more</text></g>
<rect class="nj-heat-na" x="420" y="482" width="40" height="20" rx="3"/>
<text class="nj-charts-tick" x="440" y="496">n/a</text>
<text class="nj-charts-tick nj-charts-tick--l" x="468" y="496">no A&#8203;PI for it</text>
</svg>

</div>

<p class="nj-caption" markdown>The use cases on the x86-64 server with Clang 23. Less is better; hover over or tap a
cell for the times and the way.</p>

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-charts nj-charts--blog nj-charts--heat" viewBox="0 0 784 510" role="img" aria-labelledby="nj-blog-uc-x86-gcc13 nj-blog-uc-x86-gcc13-d" xmlns="http://www.w3.org/2000/svg">
<title id="nj-blog-uc-x86-gcc13">Use cases: time of each library relative to the fastest, x86-64 with G&#8203;CC 13</title>
<desc id="nj-blog-uc-x86-gcc13-d">Table of relative times, libraries by use case. nlohmann/json json_document validate: 1.00; nlohmann/json json_document sum: 1.10; nlohmann/json json_document select: 1.00; nlohmann/json json_document edit: 1.00 (0.82 doing less, N); nlohmann/json json_document minify: 1.00 (0.81 doing less, N); nlohmann/json json_document write: 1.00 (0.71 doing less, N); yyjson validate: 2.06; yyjson sum: 1.44; yyjson select: 1.37; yyjson edit: 1.57; yyjson minify: 1.37 (1.03 doing less, N); yyjson write: 1.08; sonic-cpp validate: no fully validating way (2.21 doing less, U); sonic-cpp sum: no fully validating way (1.28 doing less, U); sonic-cpp select: no fully validating way (1.48 doing less, U); sonic-cpp edit: no fully validating way (1.22 doing less, U); sonic-cpp minify: no fully validating way (1.40 doing less, U); sonic-cpp write: 1.50; simdjson validate: 1.93; simdjson sum: 1.00; simdjson select: 1.29 (0.56 doing less, P); simdjson edit: n/a; simdjson minify: 1.55 (0.21 doing less, P); simdjson write: 2.09; sonic-rs (Rust) validate: 1.77; sonic-rs (Rust) sum: 1.13; sonic-rs (Rust) select: 1.33; sonic-rs (Rust) edit: 1.86; sonic-rs (Rust) minify: 1.71; sonic-rs (Rust) write: 2.00; Boost.J&#8203;SON validate: 1.83; Boost.J&#8203;SON sum: 1.30; Boost.J&#8203;SON select: 2.23; Boost.J&#8203;SON edit: 2.45; Boost.J&#8203;SON minify: 2.83; Boost.J&#8203;SON write: 2.50; nlohmann/json json validate: 1.34; nlohmann/json json sum: 1.04; nlohmann/json json select: 6.05; nlohmann/json json edit: 3.37; nlohmann/json json minify: 4.13; nlohmann/json json write: 1.85; simd-json (Rust) validate: 3.31; simd-json (Rust) sum: 1.91; simd-json (Rust) select: 2.54; simd-json (Rust) edit: 2.82; simd-json (Rust) minify: 3.35; simd-json (Rust) write: 2.28; serde_json (Rust) validate: 2.19 (1.96 doing less, U); serde_json (Rust) sum: 2.35; serde_json (Rust) select: 1.70; serde_json (Rust) edit: 4.44; serde_json (Rust) minify: 4.88; serde_json (Rust) write: 2.21; Glaze validate: 2.05; Glaze sum: 4.06 (3.93 doing less, P); Glaze select: 1.39 (0.58 doing less, P); Glaze edit: 4.71; Glaze minify: 4.96 (0.70 doing less, P); Glaze write: 1.80; RapidJSON validate: 3.88 (3.36 doing less, U); RapidJSON sum: 2.67 (2.34 doing less, U); RapidJSON select: 3.39 (3.12 doing less, U); RapidJSON edit: 2.65 (2.52 doing less, U); RapidJSON minify: 3.64 (2.61 doing less, U N); RapidJSON write: 2.95.</desc>
<text class="nj-charts-tick" x="270" y="34">validate</text>
<text class="nj-charts-tick" x="362" y="34">sum</text>
<text class="nj-charts-tick" x="454" y="34">select</text>
<text class="nj-charts-tick" x="546" y="34">edit</text>
<text class="nj-charts-tick" x="638" y="34">minify</text>
<text class="nj-charts-tick" x="730" y="34">write</text>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="66" text-anchor="end">nlohmann/json json_document</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · validate&#10;1.00× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 267 µs&#10;citm_catalog.json: 664 µs&#10;canada.json: 986 µs&#10;jeopardy.json: 34,874 µs">
<rect class="nj-heat-0" x="225" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · sum&#10;1.10× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 387 µs&#10;citm_catalog.json: 1,036 µs&#10;canada.json: 3,704 µs&#10;jeopardy.json: 89,477 µs">
<rect class="nj-heat-0" x="317" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="66" text-anchor="middle">1.10</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · select&#10;1.00× the time of the fastest library (fully validating)&#10;twitter.json: 329 µs · structs (from_json)&#10;citm_catalog.json: 855 µs · parse&#10;canada.json: 1,360 µs · structs (from_json)&#10;jeopardy.json: 90,597 µs · parse">
<rect class="nj-heat-0" x="409" y="45" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit&#10;1.00× the time of the fastest library (fully validating)&#10;way: editable&#10;twitter.json: 530 µs&#10;citm_catalog.json: 1,209 µs&#10;canada.json: 5,792 µs&#10;jeopardy.json: 193,925 µs">
<rect class="nj-heat-0" x="501" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · edit, checking less&#10;0.82× the time of the fastest fully validating library&#10;twitter.json: 530 µs · editable (validates fully)&#10;citm_catalog.json: 1,209 µs · editable (validates fully)&#10;canada.json: 2,621 µs · editable (source numbers) (validates fully)&#10;jeopardy.json: 193,925 µs · editable (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="547" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="60" text-anchor="middle">0.82</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify&#10;1.00× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 475 µs&#10;citm_catalog.json: 1,102 µs&#10;canada.json: 5,414 µs&#10;jeopardy.json: 144,877 µs">
<rect class="nj-heat-0" x="593" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · minify, checking less&#10;0.81× the time of the fastest fully validating library&#10;twitter.json: 471 µs · parse + dump (source numbers) (validates fully)&#10;citm_catalog.json: 1,102 µs · parse + dump (validates fully)&#10;canada.json: 2,372 µs · parse + dump (source numbers) (validates fully)&#10;jeopardy.json: 144,877 µs · parse + dump (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="639" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="60" text-anchor="middle">0.81</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="73" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write&#10;1.00× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 152 µs&#10;citm_catalog.json: 260 µs&#10;canada.json: 3,811 µs&#10;jeopardy.json: 72,196 µs">
<rect class="nj-heat-0" x="685" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="707.5" y="66" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json_document · write, checking less&#10;0.71× the time of the fastest fully validating library&#10;twitter.json: 147 µs · dump (source numbers) (validates fully)&#10;citm_catalog.json: 260 µs · dump (validates fully)&#10;canada.json: 997 µs · dump (source numbers) (validates fully)&#10;jeopardy.json: 71,822 µs · dump (source numbers) (validates fully)&#10;copies each number&#x27;s text instead of formatting it (number_format::source)">
<rect class="nj-heat-0" x="731" y="45" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="752.5" y="60" text-anchor="middle">0.71</text>
<text class="nj-charts-cell nj-charts-cell--small" x="752.5" y="73" text-anchor="middle">N</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="102" text-anchor="end">yyjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · validate&#10;2.06× the time of the fastest library (fully validating)&#10;twitter.json: 394 µs · insitu (copy)&#10;citm_catalog.json: 984 µs · read&#10;canada.json: 2,222 µs · read (raw numbers)&#10;jeopardy.json: 128,528 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="225" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="102" text-anchor="middle">2.06</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · sum&#10;1.44× the time of the fastest library (fully validating)&#10;twitter.json: 443 µs · insitu (copy)&#10;citm_catalog.json: 1,146 µs · insitu (copy)&#10;canada.json: 5,974 µs · read&#10;jeopardy.json: 129,054 µs · read&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="317" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="102" text-anchor="middle">1.44</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · select&#10;1.37× the time of the fastest library (fully validating)&#10;twitter.json: 397 µs · read&#10;citm_catalog.json: 994 µs · insitu (copy)&#10;canada.json: 2,228 µs · read (raw numbers)&#10;jeopardy.json: 140,073 µs · read (raw numbers)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="409" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="102" text-anchor="middle">1.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · edit&#10;1.57× the time of the fastest library (fully validating)&#10;twitter.json: 841 µs · insitu (copy) + mut copy&#10;citm_catalog.json: 1,719 µs · mut copy&#10;canada.json: 9,803 µs · insitu (copy) + mut copy&#10;jeopardy.json: 309,935 µs · insitu (copy) + mut copy&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="501" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="102" text-anchor="middle">1.57</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify&#10;1.37× the time of the fastest library (fully validating)&#10;twitter.json: 600 µs · insitu (copy) + write&#10;citm_catalog.json: 1,316 µs · insitu (copy) + write&#10;canada.json: 9,151 µs · read + write&#10;jeopardy.json: 201,645 µs · read + write&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-1" x="593" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="102" text-anchor="middle">1.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · minify, checking less&#10;1.03× the time of the fastest fully validating library&#10;twitter.json: 600 µs · read (raw numbers) + write (validates fully)&#10;citm_catalog.json: 1,264 µs · read (raw numbers) + write (validates fully)&#10;canada.json: 2,994 µs · read (raw numbers) + write (validates fully)&#10;jeopardy.json: 201,645 µs · read + write (validates fully)&#10;copies each number&#x27;s text instead of formatting it (YYJSON_READ_NUMBER_AS_RAW)">
<rect class="nj-heat-0" x="639" y="81" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="96" text-anchor="middle">1.03</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="109" text-anchor="middle">N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="yyjson · write&#10;1.08× the time of the fastest library (fully validating)&#10;way: write&#10;twitter.json: 180 µs&#10;citm_catalog.json: 325 µs&#10;canada.json: 3,548 µs&#10;jeopardy.json: 71,044 µs">
<rect class="nj-heat-0" x="685" y="81" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="102" text-anchor="middle">1.08</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="138" text-anchor="end">sonic-cpp</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · validate, checking less&#10;2.21× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 409 µs&#10;citm_catalog.json: 1,025 µs&#10;canada.json: 3,561 µs&#10;jeopardy.json: 96,607 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-2" x="225" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="132" text-anchor="middle">2.21</text>
<text class="nj-charts-cell nj-charts-cell--small" x="270" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · sum, checking less&#10;1.28× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 459 µs&#10;citm_catalog.json: 1,209 µs&#10;canada.json: 4,247 µs&#10;jeopardy.json: 103,731 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="317" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="132" text-anchor="middle">1.28</text>
<text class="nj-charts-cell nj-charts-cell--small" x="362" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · select, checking less&#10;1.48× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 412 µs&#10;citm_catalog.json: 1,044 µs&#10;canada.json: 3,632 µs&#10;jeopardy.json: 106,188 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="409" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="132" text-anchor="middle">1.48</text>
<text class="nj-charts-cell nj-charts-cell--small" x="454" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · edit, checking less&#10;1.22× the time of the fastest fully validating library&#10;way: Document&#10;twitter.json: 632 µs&#10;citm_catalog.json: 1,583 µs&#10;canada.json: 8,734 µs&#10;jeopardy.json: 184,592 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="501" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="132" text-anchor="middle">1.22</text>
<text class="nj-charts-cell nj-charts-cell--small" x="546" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · minify, checking less&#10;1.40× the time of the fastest fully validating library&#10;way: Document + Serialize&#10;twitter.json: 647 µs&#10;citm_catalog.json: 1,563 µs&#10;canada.json: 8,917 µs&#10;jeopardy.json: 176,625 µs&#10;trusts U&#8203;TF-8: sonic-cpp 1.0.2 doesn&#x27;t check it">
<rect class="nj-heat-1" x="593" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="132" text-anchor="middle">1.40</text>
<text class="nj-charts-cell nj-charts-cell--small" x="638" y="145" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-cpp · write&#10;1.50× the time of the fastest library (fully validating)&#10;way: Serialize&#10;twitter.json: 268 µs&#10;citm_catalog.json: 543 µs&#10;canada.json: 5,057 µs&#10;jeopardy.json: 75,734 µs">
<rect class="nj-heat-2" x="685" y="117" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="138" text-anchor="middle">1.50</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="174" text-anchor="end">simdjson</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · validate&#10;1.93× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 309 µs&#10;citm_catalog.json: 737 µs&#10;canada.json: 3,183 µs&#10;jeopardy.json: 115,296 µs">
<rect class="nj-heat-2" x="225" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="174" text-anchor="middle">1.93</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · sum&#10;1.00× the time of the fastest library (fully validating)&#10;way: On-Demand&#10;twitter.json: 356 µs&#10;citm_catalog.json: 819 µs&#10;canada.json: 3,291 µs&#10;jeopardy.json: 94,267 µs">
<rect class="nj-heat-0" x="317" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="174" text-anchor="middle">1.00</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select&#10;1.29× the time of the fastest library (fully validating)&#10;way: D&#8203;OM&#10;twitter.json: 323 µs&#10;citm_catalog.json: 748 µs&#10;canada.json: 3,189 µs&#10;jeopardy.json: 126,288 µs">
<rect class="nj-heat-1" x="409" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="174" text-anchor="middle">1.29</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · select, checking less&#10;0.56× the time of the fastest fully validating library&#10;twitter.json: 186 µs · On-Demand&#10;citm_catalog.json: 508 µs · On-Demand&#10;canada.json: 707 µs · On-Demand&#10;jeopardy.json: 50,215 µs · On-Demand (key selectors)&#10;reads lazily: On-Demand reads only what you ask for and steps over the rest by matching brackets">
<rect class="nj-heat-0" x="455" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="168" text-anchor="middle">0.56</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · edit&#10;simdjson&#x27;s documents are read-only: it has no A&#8203;PI to change a value and write the result">
<rect class="nj-heat-na" x="501" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-tick" x="546" y="174">n/a</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify&#10;1.55× the time of the fastest library (fully validating)&#10;way: D&#8203;OM + to_string&#10;twitter.json: 689 µs&#10;citm_catalog.json: 1,394 µs&#10;canada.json: 8,457 µs&#10;jeopardy.json: 292,576 µs">
<rect class="nj-heat-2" x="593" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="174" text-anchor="middle">1.55</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · minify, checking less&#10;0.21× the time of the fastest fully validating library&#10;way: minify&#10;twitter.json: 122 µs&#10;citm_catalog.json: 336 µs&#10;canada.json: 426 µs&#10;jeopardy.json: 49,731 µs&#10;simdjson::minify() only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="153" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="168" text-anchor="middle">0.21</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="181" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simdjson · write&#10;2.09× the time of the fastest library (fully validating)&#10;way: to_string&#10;twitter.json: 360 µs&#10;citm_catalog.json: 636 µs&#10;canada.json: 5,363 µs&#10;jeopardy.json: 169,032 µs">
<rect class="nj-heat-2" x="685" y="153" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="174" text-anchor="middle">2.09</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="210" text-anchor="end">sonic-rs (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · validate&#10;1.77× the time of the fastest library (fully validating)&#10;way: IgnoredAny&#10;twitter.json: 501 µs&#10;citm_catalog.json: 970 µs&#10;canada.json: 2,249 µs&#10;jeopardy.json: 54,369 µs">
<rect class="nj-heat-2" x="225" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="210" text-anchor="middle">1.77</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · sum&#10;1.13× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 501 µs&#10;citm_catalog.json: 1,123 µs&#10;canada.json: 4,397 µs&#10;jeopardy.json: 59,583 µs">
<rect class="nj-heat-0" x="317" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="210" text-anchor="middle">1.13</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · select&#10;1.33× the time of the fastest library (fully validating)&#10;way: structs&#10;twitter.json: 504 µs&#10;citm_catalog.json: 1,033 µs&#10;canada.json: 2,328 µs&#10;jeopardy.json: 90,486 µs">
<rect class="nj-heat-1" x="409" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="210" text-anchor="middle">1.33</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · edit&#10;1.86× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,197 µs&#10;citm_catalog.json: 2,389 µs&#10;canada.json: 7,744 µs&#10;jeopardy.json: 390,952 µs">
<rect class="nj-heat-2" x="501" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="210" text-anchor="middle">1.86</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · minify&#10;1.71× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 1,000 µs&#10;citm_catalog.json: 2,097 µs&#10;canada.json: 7,795 µs&#10;jeopardy.json: 215,280 µs">
<rect class="nj-heat-2" x="593" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="210" text-anchor="middle">1.71</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="sonic-rs (Rust) · write&#10;2.00× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 434 µs&#10;citm_catalog.json: 927 µs&#10;canada.json: 3,987 µs&#10;jeopardy.json: 109,176 µs">
<rect class="nj-heat-2" x="685" y="189" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="210" text-anchor="middle">2.00</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="246" text-anchor="end">Boost.J&#8203;SON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · validate&#10;1.83× the time of the fastest library (fully validating)&#10;twitter.json: 730 µs · S&#8203;AX (numbers: none)&#10;citm_catalog.json: 934 µs · S&#8203;AX (numbers: none)&#10;canada.json: 1,637 µs · S&#8203;AX (numbers: none)&#10;jeopardy.json: 60,745 µs · S&#8203;AX">
<rect class="nj-heat-2" x="225" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="246" text-anchor="middle">1.83</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · sum&#10;1.30× the time of the fastest library (fully validating)&#10;way: S&#8203;AX&#10;twitter.json: 746 µs&#10;citm_catalog.json: 1,025 µs&#10;canada.json: 5,370 µs&#10;jeopardy.json: 63,333 µs">
<rect class="nj-heat-1" x="317" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="246" text-anchor="middle">1.30</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · select&#10;2.23× the time of the fastest library (fully validating)&#10;twitter.json: 899 µs · parse_into structs&#10;citm_catalog.json: 1,353 µs · parse_into structs&#10;canada.json: 7,011 µs · parse&#10;jeopardy.json: 100,039 µs · parse_into structs">
<rect class="nj-heat-2" x="409" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="246" text-anchor="middle">2.23</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · edit&#10;2.45× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 1,889 µs&#10;citm_catalog.json: 2,952 µs&#10;canada.json: 13,537 µs&#10;jeopardy.json: 346,542 µs">
<rect class="nj-heat-2" x="501" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="246" text-anchor="middle">2.45</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · minify&#10;2.83× the time of the fastest library (fully validating)&#10;way: parse + serialize&#10;twitter.json: 1,907 µs&#10;citm_catalog.json: 2,950 µs&#10;canada.json: 13,662 µs&#10;jeopardy.json: 342,183 µs">
<rect class="nj-heat-3" x="593" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="246" text-anchor="middle">2.83</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Boost.J&#8203;SON · write&#10;2.50× the time of the fastest library (fully validating)&#10;way: serialize&#10;twitter.json: 474 µs&#10;citm_catalog.json: 1,003 µs&#10;canada.json: 6,012 µs&#10;jeopardy.json: 148,120 µs">
<rect class="nj-heat-2" x="685" y="225" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="246" text-anchor="middle">2.50</text>
</g>
<text class="nj-charts-rowlabel nj-charts-name-json" x="216" y="282" text-anchor="end">nlohmann/json json</text>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · validate&#10;1.34× the time of the fastest library (fully validating)&#10;way: accept&#10;twitter.json: 312 µs&#10;citm_catalog.json: 686 µs&#10;canada.json: 2,345 µs&#10;jeopardy.json: 38,948 µs">
<rect class="nj-heat-1" x="225" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="282" text-anchor="middle">1.34</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · sum&#10;1.04× the time of the fastest library (fully validating)&#10;way: sax&#10;twitter.json: 451 µs&#10;citm_catalog.json: 941 µs&#10;canada.json: 3,816 µs&#10;jeopardy.json: 64,406 µs">
<rect class="nj-heat-0" x="317" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="282" text-anchor="middle">1.04</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · select&#10;6.05× the time of the fastest library (fully validating)&#10;way: parse&#10;twitter.json: 3,032 µs&#10;citm_catalog.json: 4,466 µs&#10;canada.json: 9,085 µs&#10;jeopardy.json: 376,812 µs">
<rect class="nj-heat-4" x="409" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="282" text-anchor="middle">6.05</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · edit&#10;3.37× the time of the fastest library (fully validating)&#10;twitter.json: 2,503 µs · ordered_json&#10;citm_catalog.json: 4,414 µs · ordered_json&#10;canada.json: 13,479 µs · parse&#10;jeopardy.json: 622,816 µs · ordered_json">
<rect class="nj-heat-3" x="501" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="282" text-anchor="middle">3.37</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · minify&#10;4.13× the time of the fastest library (fully validating)&#10;way: parse + dump&#10;twitter.json: 3,417 µs&#10;citm_catalog.json: 5,153 µs&#10;canada.json: 13,425 µs&#10;jeopardy.json: 504,511 µs">
<rect class="nj-heat-3" x="593" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="282" text-anchor="middle">4.13</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="nlohmann/json json · write&#10;1.85× the time of the fastest library (fully validating)&#10;way: dump&#10;twitter.json: 413 µs&#10;citm_catalog.json: 617 µs&#10;canada.json: 4,036 µs&#10;jeopardy.json: 124,865 µs">
<rect class="nj-heat-2" x="685" y="261" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="282" text-anchor="middle">1.85</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="318" text-anchor="end">simd-json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · validate&#10;3.31× the time of the fastest library (fully validating)&#10;way: tape (copy)&#10;twitter.json: 567 µs&#10;citm_catalog.json: 1,430 µs&#10;canada.json: 4,359 µs&#10;jeopardy.json: 207,551 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="318" text-anchor="middle">3.31</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · sum&#10;1.91× the time of the fastest library (fully validating)&#10;way: visitor (copy)&#10;twitter.json: 681 µs&#10;citm_catalog.json: 1,650 µs&#10;canada.json: 5,083 µs&#10;jeopardy.json: 210,185 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="317" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="318" text-anchor="middle">1.91</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · select&#10;2.54× the time of the fastest library (fully validating)&#10;way: structs (copy)&#10;twitter.json: 679 µs&#10;citm_catalog.json: 1,731 µs&#10;canada.json: 5,144 µs&#10;jeopardy.json: 239,164 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="318" text-anchor="middle">2.54</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · edit&#10;2.82× the time of the fastest library (fully validating)&#10;twitter.json: 1,862 µs · borrowed (copy)&#10;citm_catalog.json: 4,194 µs · borrowed (copy)&#10;canada.json: 14,896 µs · owned (copy)&#10;jeopardy.json: 391,369 µs · borrowed (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="318" text-anchor="middle">2.82</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · minify&#10;3.35× the time of the fastest library (fully validating)&#10;way: borrowed (copy)&#10;twitter.json: 1,889 µs&#10;citm_catalog.json: 4,196 µs&#10;canada.json: 15,716 µs&#10;jeopardy.json: 414,377 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="593" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="318" text-anchor="middle">3.35</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="simd-json (Rust) · write&#10;2.28× the time of the fastest library (fully validating)&#10;way: borrowed&#10;twitter.json: 582 µs&#10;citm_catalog.json: 800 µs&#10;canada.json: 5,147 µs&#10;jeopardy.json: 122,623 µs">
<rect class="nj-heat-2" x="685" y="297" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="318" text-anchor="middle">2.28</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="354" text-anchor="end">serde_json (Rust)</text>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate&#10;2.19× the time of the fastest library (fully validating)&#10;way: from_utf8 + IgnoredAny&#10;twitter.json: 624 µs&#10;citm_catalog.json: 1,440 µs&#10;canada.json: 2,406 µs&#10;jeopardy.json: 64,720 µs">
<rect class="nj-heat-2" x="225" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="354" text-anchor="middle">2.19</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · validate, checking less&#10;1.96× the time of the fastest fully validating library&#10;way: IgnoredAny&#10;twitter.json: 484 µs&#10;citm_catalog.json: 1,370 µs&#10;canada.json: 2,314 µs&#10;jeopardy.json: 58,247 µs&#10;trusts U&#8203;TF-8 in the strings it skips (from_slice); strings it reads are checked">
<rect class="nj-heat-2" x="271" y="333" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="348" text-anchor="middle">1.96</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="361" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · sum&#10;2.35× the time of the fastest library (fully validating)&#10;way: visitor&#10;twitter.json: 1,311 µs&#10;citm_catalog.json: 2,288 µs&#10;canada.json: 7,127 µs&#10;jeopardy.json: 129,497 µs">
<rect class="nj-heat-2" x="317" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="362" y="354" text-anchor="middle">2.35</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · select&#10;1.70× the time of the fastest library (fully validating)&#10;way: from_utf8 + structs&#10;twitter.json: 701 µs&#10;citm_catalog.json: 1,532 µs&#10;canada.json: 2,529 µs&#10;jeopardy.json: 107,316 µs">
<rect class="nj-heat-2" x="409" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="454" y="354" text-anchor="middle">1.70</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · edit&#10;4.44× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,042 µs&#10;citm_catalog.json: 6,586 µs&#10;canada.json: 16,631 µs&#10;jeopardy.json: 632,766 µs">
<rect class="nj-heat-3" x="501" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="354" text-anchor="middle">4.44</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · minify&#10;4.88× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 4,012 µs&#10;citm_catalog.json: 6,583 µs&#10;canada.json: 17,306 µs&#10;jeopardy.json: 509,702 µs">
<rect class="nj-heat-3" x="593" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="638" y="354" text-anchor="middle">4.88</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="serde_json (Rust) · write&#10;2.21× the time of the fastest library (fully validating)&#10;way: Value&#10;twitter.json: 550 µs&#10;citm_catalog.json: 887 µs&#10;canada.json: 4,005 µs&#10;jeopardy.json: 134,163 µs">
<rect class="nj-heat-2" x="685" y="333" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="354" text-anchor="middle">2.21</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="390" text-anchor="end">Glaze</text>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · validate&#10;2.05× the time of the fastest library (fully validating)&#10;way: validate_json&#10;twitter.json: 584 µs&#10;citm_catalog.json: 1,402 µs&#10;canada.json: 1,837 µs&#10;jeopardy.json: 71,382 µs">
<rect class="nj-heat-2" x="225" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="270" y="390" text-anchor="middle">2.05</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum&#10;4.06× the time of the fastest library (fully validating)&#10;way: generic (double, strict)&#10;twitter.json: 2,341 µs&#10;citm_catalog.json: 4,037 µs&#10;canada.json: 10,434 µs&#10;jeopardy.json: 249,828 µs">
<rect class="nj-heat-3" x="317" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="390" text-anchor="middle">4.06</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · sum, checking less&#10;3.93× the time of the fastest fully validating library&#10;twitter.json: 2,341 µs · generic (double, strict) (validates fully)&#10;citm_catalog.json: 4,037 µs · generic (double, strict) (validates fully)&#10;canada.json: 10,434 µs · generic (double, strict) (validates fully)&#10;jeopardy.json: 219,119 µs · lazy_json&#10;reads lazily: lazy_json reads only what you ask for and steps over the rest">
<rect class="nj-heat-3" x="363" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="384" text-anchor="middle">3.93</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select&#10;1.39× the time of the fastest library (fully validating)&#10;way: structs (validate_skipped)&#10;twitter.json: 523 µs&#10;citm_catalog.json: 1,473 µs&#10;canada.json: 1,853 µs&#10;jeopardy.json: 89,506 µs">
<rect class="nj-heat-1" x="409" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="390" text-anchor="middle">1.39</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · select, checking less&#10;0.58× the time of the fastest fully validating library&#10;way: structs&#10;twitter.json: 338 µs&#10;citm_catalog.json: 406 µs&#10;canada.json: 434 µs&#10;jeopardy.json: 66,029 µs&#10;reads into structs and steps over fields it doesn&#x27;t know without checking them (validate_skipped checks them too)">
<rect class="nj-heat-0" x="455" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="384" text-anchor="middle">0.58</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · edit&#10;4.71× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,474 µs&#10;citm_catalog.json: 6,531 µs&#10;canada.json: 23,193 µs&#10;jeopardy.json: 673,526 µs">
<rect class="nj-heat-3" x="501" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="546" y="390" text-anchor="middle">4.71</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify&#10;4.96× the time of the fastest library (fully validating)&#10;way: generic (strict)&#10;twitter.json: 3,359 µs&#10;citm_catalog.json: 6,437 µs&#10;canada.json: 23,896 µs&#10;jeopardy.json: 480,814 µs">
<rect class="nj-heat-3" x="593" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="390" text-anchor="middle">4.96</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · minify, checking less&#10;0.70× the time of the fastest fully validating library&#10;way: minify_json&#10;twitter.json: 417 µs&#10;citm_catalog.json: 1,116 µs&#10;canada.json: 2,113 µs&#10;jeopardy.json: 97,812 µs&#10;minify_json only removes whitespace, without parsing the values">
<rect class="nj-heat-0" x="639" y="369" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="384" text-anchor="middle">0.70</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="397" text-anchor="middle">P</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="Glaze · write&#10;1.80× the time of the fastest library (fully validating)&#10;way: generic&#10;twitter.json: 336 µs&#10;citm_catalog.json: 682 µs&#10;canada.json: 3,750 µs&#10;jeopardy.json: 133,730 µs">
<rect class="nj-heat-2" x="685" y="369" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="390" text-anchor="middle">1.80</text>
</g>
<text class="nj-charts-rowlabel " x="216" y="426" text-anchor="end">RapidJSON</text>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate&#10;3.88× the time of the fastest library (fully validating)&#10;twitter.json: 1,201 µs · insitu (copy)&#10;citm_catalog.json: 1,931 µs · insitu (copy)&#10;canada.json: 4,114 µs · S&#8203;AX (string stream, default precision)&#10;jeopardy.json: 145,137 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="225" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="247.5" y="426" text-anchor="middle">3.88</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · validate, checking less&#10;3.36× the time of the fastest fully validating library&#10;twitter.json: 1,033 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,487 µs · S&#8203;AX (default precision) (no encoding check)&#10;canada.json: 3,966 µs · S&#8203;AX (string stream, default precision) (no encoding check)&#10;jeopardy.json: 127,587 µs · S&#8203;AX (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="271" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="292.5" y="420" text-anchor="middle">3.36</text>
<text class="nj-charts-cell nj-charts-cell--small" x="292.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum&#10;2.67× the time of the fastest library (fully validating)&#10;twitter.json: 1,256 µs · insitu (copy)&#10;citm_catalog.json: 2,114 µs · insitu (copy)&#10;canada.json: 11,059 µs · S&#8203;AX (string stream)&#10;jeopardy.json: 155,532 µs · insitu (copy)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="317" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="339.5" y="426" text-anchor="middle">2.67</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · sum, checking less&#10;2.34× the time of the fastest fully validating library&#10;twitter.json: 1,085 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,750 µs · S&#8203;AX (no encoding check)&#10;canada.json: 11,008 µs · S&#8203;AX (string stream) (no encoding check)&#10;jeopardy.json: 128,734 µs · S&#8203;AX (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-2" x="363" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="384.5" y="420" text-anchor="middle">2.34</text>
<text class="nj-charts-cell nj-charts-cell--small" x="384.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select&#10;3.39× the time of the fastest library (fully validating)&#10;way: insitu (copy)&#10;twitter.json: 1,207 µs&#10;citm_catalog.json: 1,947 µs&#10;canada.json: 11,910 µs&#10;jeopardy.json: 164,386 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="409" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="431.5" y="426" text-anchor="middle">3.39</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · select, checking less&#10;3.12× the time of the fastest fully validating library&#10;twitter.json: 1,037 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 1,847 µs · insitu (copy) (no encoding check)&#10;canada.json: 11,692 µs · Document (no encoding check)&#10;jeopardy.json: 147,489 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="455" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="476.5" y="420" text-anchor="middle">3.12</text>
<text class="nj-charts-cell nj-charts-cell--small" x="476.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit&#10;2.65× the time of the fastest library (fully validating)&#10;way: insitu (copy)&#10;twitter.json: 1,920 µs&#10;citm_catalog.json: 2,977 µs&#10;canada.json: 21,152 µs&#10;jeopardy.json: 293,851 µs&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="501" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="523.5" y="426" text-anchor="middle">2.65</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · edit, checking less&#10;2.52× the time of the fastest fully validating library&#10;twitter.json: 1,747 µs · insitu (copy) (no encoding check)&#10;citm_catalog.json: 2,823 µs · insitu (copy) (no encoding check)&#10;canada.json: 20,998 µs · Document (no encoding check)&#10;jeopardy.json: 280,165 µs · insitu (copy) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;(copy): parses in place, on a copy of the input that is part of the time">
<rect class="nj-heat-3" x="547" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="568.5" y="420" text-anchor="middle">2.52</text>
<text class="nj-charts-cell nj-charts-cell--small" x="568.5" y="433" text-anchor="middle">U</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify&#10;3.64× the time of the fastest library (fully validating)&#10;twitter.json: 2,746 µs · S&#8203;AX to Writer (string stream)&#10;citm_catalog.json: 3,162 µs · S&#8203;AX to Writer (string stream)&#10;canada.json: 21,674 µs · S&#8203;AX to Writer&#10;jeopardy.json: 381,832 µs · S&#8203;AX to Writer (string stream)">
<rect class="nj-heat-3" x="593" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="615.5" y="426" text-anchor="middle">3.64</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · minify, checking less&#10;2.61× the time of the fastest fully validating library&#10;twitter.json: 1,824 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;citm_catalog.json: 2,672 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;canada.json: 15,166 µs · S&#8203;AX to Writer (raw numbers) (no encoding check)&#10;jeopardy.json: 259,100 µs · S&#8203;AX to Writer (string stream) (no encoding check)&#10;trusts U&#8203;TF-8: RapidJSON&#x27;s default (kParseValidateEncodingFlag checks it)&#10;copies each number&#x27;s text instead of formatting it (kParseNumbersAsStringsFlag)">
<rect class="nj-heat-3" x="639" y="405" width="44" height="34" rx="3"/>
<text class="nj-charts-cell" x="660.5" y="420" text-anchor="middle">2.61</text>
<text class="nj-charts-cell nj-charts-cell--small" x="660.5" y="433" text-anchor="middle">U N</text>
</g>
<g class="nj-heat-cell" tabindex="0" data-tip="RapidJSON · write&#10;2.95× the time of the fastest library (fully validating)&#10;way: Writer&#10;twitter.json: 661 µs&#10;citm_catalog.json: 1,015 µs&#10;canada.json: 8,980 µs&#10;jeopardy.json: 136,957 µs">
<rect class="nj-heat-3" x="685" y="405" width="90" height="34" rx="3"/>
<text class="nj-charts-cell" x="730" y="426" text-anchor="middle">2.95</text>
</g>
<text class="nj-charts-tick nj-charts-tick--l" x="8" y="472">time relative to the fastest fully validating library, less is better</text>
<g><rect class="nj-heat-0" x="8" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="46" y="496" text-anchor="middle">below 1.15</text></g>
<g><rect class="nj-heat-1" x="88" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="126" y="496" text-anchor="middle">1.15 to 1.5</text></g>
<g><rect class="nj-heat-2" x="168" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="206" y="496" text-anchor="middle">1.5 to 2.5</text></g>
<g><rect class="nj-heat-3" x="248" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="286" y="496" text-anchor="middle">2.5 to 5</text></g>
<g><rect class="nj-heat-4" x="328" y="482" width="76" height="20" rx="3"/>
<text class="nj-charts-cell nj-charts-cell--small" x="366" y="496" text-anchor="middle">5 and more</text></g>
<rect class="nj-heat-na" x="420" y="482" width="40" height="20" rx="3"/>
<text class="nj-charts-tick" x="440" y="496">n/a</text>
<text class="nj-charts-tick nj-charts-tick--l" x="468" y="496">no A&#8203;PI for it</text>
</svg>

</div>

<p class="nj-caption" markdown>The use cases on the x86-64 server with GCC 13.4. Less is better; hover over or tap a
cell for the times and the way.</p>

??? info "Times in µs on the Apple M1 Max"

    **validate**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | accept | 172 | 313 | 905 | 20,926 | 0.9 |
    | yyjson | insitu (copy), read | 183 | 476 | 1,487 | 30,922 | 0.9 |
    | nlohmann/json `json` | accept | 234 | 456 | 1,253 | 27,563 | 1.1 |
    | simdjson | DOM | 215 | 460 | 1,890 | 28,890 | 1.1 |
    | sonic-rs (Rust) | Value | 326 | 681 | 1,939 | 31,450 | 1.4 |
    | Glaze | validate_json | 333 | 854 | 1,302 | 46,251 | 1.4 |
    | simd-json (Rust) | tape (copy) | 289 | 698 | 2,278 | 38,874 | 1.7 |
    | sonic-cpp | Document [U] | – (U 382) | – (U 985) | – (U 2,579) | – (U 40,996) | – (U 1.7) |
    | serde_json (Rust) | IgnoredAny [U], from_utf8 + IgnoredAny | 452 (U 354) | 1,103 (U 1,047) | 1,556 (U 1,451) | 46,517 (U 44,984) | 2.0 (U 1.7) |
    | Boost.JSON | SAX, SAX (numbers: none) | 540 | 990 | 1,449 | 54,480 | 2.4 |
    | RapidJSON | SAX (default precision), SAX (string stream, default precision), SAX (string stream, default precision) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,318 (U 706) | 1,391 (U 1,033) | 1,971 | 133,695 (U 64,732) | 6.1 (U 2.7) |

    **sum**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse | 219 | 493 | 1,803 | 28,898 | 1.2 |
    | yyjson | insitu (copy), read | 231 | 571 | 1,875 | 37,817 | 1.1 |
    | simdjson | DOM, On-Demand | 249 | 572 | 2,398 | 34,994 | 1.3 |
    | nlohmann/json `json` | sax | 303 | 602 | 2,208 | 44,688 | 1.6 |
    | sonic-rs (Rust) | visitor | 364 | 778 | 2,703 | 41,361 | 1.7 |
    | simd-json (Rust) | visitor (copy) | 354 | 866 | 2,717 | 47,518 | 2.0 |
    | sonic-cpp | Document [U] | – (U 428) | – (U 1,098) | – (U 2,975) | – (U 48,487) | – (U 1.9) |
    | Boost.JSON | SAX | 538 | 1,028 | 3,084 | 54,765 | 2.3 |
    | serde_json (Rust) | visitor | 652 | 1,242 | 4,772 | 66,568 | 2.5 |
    | Glaze | generic (double) [P], generic (double, strict), lazy_json [P] | 974 | 2,057 | 6,338 | 100,272 | 4.9 (P 3.5) |
    | RapidJSON | SAX, SAX (string stream), SAX (string stream) (no encoding check) [U], insitu (copy) (no encoding check) [U] | 1,332 (U 738) | 1,472 (U 1,157) | 6,448 | 136,330 (U 71,646) | 6.2 (U 2.9) |

    **select**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse | 183 | 363 | 944 | 24,801 | 1.0 |
    | yyjson | insitu (copy), read, read (raw numbers) | 191 | 480 | 1,489 | 32,777 | 1.1 |
    | simdjson | DOM, On-Demand (key selectors) [P], On-Demand [P], On-Demand structs [P] | 192 (P 128) | 454 (P 356) | 1,893 (P 571) | 30,714 (P 19,633) | 1.2 (P 0.8) |
    | Glaze | structs (validate_skipped), structs [P] | 314 (P 238) | 852 (P 253) | 1,303 (P 310) | 47,692 (P 36,013) | 1.4 (P 1.2) |
    | sonic-rs (Rust) | Value | 333 | 691 | 1,936 | 40,660 | 1.7 |
    | sonic-cpp | Document [U] | – (U 385) | – (U 993) | – (U 2,611) | – (U 46,356) | – (U 1.7) |
    | simd-json (Rust) | structs (copy) | 364 | 914 | 2,657 | 57,697 | 2.1 |
    | serde_json (Rust) | from_utf8 + structs, structs [U] | 480 (U 410) | 1,125 (U 1,084) | 1,560 (U 1,455) | 62,378 | 2.3 (U 1.9) |
    | Boost.JSON | parse, parse_into structs | 623 | 1,208 | 3,638 | 67,923 | 2.7 |
    | nlohmann/json `json` | parse | 1,208 | 2,128 | 5,088 | 163,712 | 6.6 |
    | RapidJSON | Document (string stream), Document (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,314 (U 701) | 1,578 (U 1,166) | 6,814 | 144,649 (U 67,617) | 6.6 (U 2.8) |

    **edit**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | editable, editable (source numbers) [N] | 288 | 559 | 2,737 (N 1,504) | 58,019 | 1.9 |
    | yyjson | insitu (copy) + mut copy, mut copy | 440 | 904 | 3,692 | 84,466 | 2.4 |
    | sonic-cpp | Document [U] | – (U 488) | – (U 1,218) | – (U 5,662) | – (U 63,697) | – (U 2.6) |
    | sonic-rs (Rust) | Value | 634 | 1,257 | 4,396 | 140,936 | 3.8 |
    | simd-json (Rust) | borrowed (copy) | 948 | 2,102 | 7,654 | 110,693 | 5.4 |
    | nlohmann/json `json` | ordered_json, parse | 1,115 | 2,065 | 7,348 | 162,216 | 6.3 |
    | Boost.JSON | parse | 1,355 | 1,997 | 6,522 | 157,849 | 6.6 |
    | Glaze | generic (strict), generic [P] | 1,527 | 3,216 | 11,033 | 183,648 | 8.4 |
    | RapidJSON | Document, Document (string stream), insitu (copy), insitu (copy) (no encoding check) [U] | 1,924 (U 1,356) | 2,393 (U 1,992) | 13,711 | 224,328 (U 147,902) | 10.5 (U 6.5) |
    | serde_json (Rust) | Value | 2,009 | 3,316 | 9,666 | 251,931 | 9.6 |

    **minify**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse + dump, parse + dump (source numbers) [N] | 261 (N 252) | 496 | 2,570 (N 1,343) | 37,624 | 1.5 |
    | yyjson | insitu (copy) + write, read (raw numbers) + write [N], read + write | 298 | 642 | 3,222 (N 2,523) | 51,001 | 1.6 |
    | simdjson | DOM + to_string, minify [P] | 425 (P 62.5) | 850 (P 168) | 5,094 (P 227) | 61,202 (P 5,756) | 2.3 (P 0.3) |
    | sonic-rs (Rust) | Value | 535 | 1,134 | 4,377 | 64,832 | 3.0 |
    | sonic-cpp | Document + Serialize [U] | – (U 504) | – (U 1,217) | – (U 5,634) | – (U 61,988) | – (U 2.5) |
    | simd-json (Rust) | borrowed (copy) | 952 | 2,111 | 7,658 | 108,130 | 5.5 |
    | Boost.JSON | parse + serialize | 1,407 | 2,003 | 6,555 | 154,865 | 6.8 |
    | nlohmann/json `json` | parse + dump | 1,446 | 2,406 | 7,328 | 182,132 | 7.7 |
    | RapidJSON | Document + Writer, SAX to Writer, SAX to Writer (raw numbers) [N], SAX to Writer (string stream), SAX to Writer (string stream) (no encoding check) [U] | 1,523 (U 1,044) | 1,803 (U 1,499) | 14,378 (N 11,568) | 174,958 (U 123,908) | 8.0 (U 4.9) |
    | Glaze | generic (strict), minify_json [P] | 1,512 (P 284) | 3,245 (P 747) | 11,112 (P 1,746) | 172,173 (P 40,439) | 8.1 (P 1.4) |
    | serde_json (Rust) | Value | 2,004 | 3,290 | 9,792 | 227,369 | 9.5 |

    **write**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | dump, dump (source numbers) [N] | 76.2 (N 72.8) | 139 | 1,625 (N 398) | 14,861 | 0.5 |
    | yyjson | write | 101 | 167 | 1,719 | 19,937 | 0.7 |
    | sonic-cpp | Serialize | 114 | 240 | 3,109 | 20,327 | 0.9 |
    | nlohmann/json `json` | dump | 216 | 287 | 2,274 | 30,928 | 1.2 |
    | Glaze | generic, generic (strict) | 212 | 476 | 1,702 | 34,032 | 1.3 |
    | simdjson | to_string | 201 | 416 | 3,186 | 32,185 | 1.3 |
    | sonic-rs (Rust) | Value | 212 | 446 | 2,419 | 33,366 | 1.5 |
    | serde_json (Rust) | Value | 322 | 490 | 2,286 | 49,967 | 2.0 |
    | simd-json (Rust) | borrowed | 355 | 478 | 2,728 | 47,412 | 1.8 |
    | Boost.JSON | serialize | 499 | 511 | 2,873 | 63,201 | 2.9 |
    | RapidJSON | Writer | 596 | 836 | 6,928 | 80,160 | 4.0 |

??? info "Times in µs on x86-64 with GCC 16.2"

    **validate**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | accept | 254 | 515 | 892 | 33,006 | 1.2 |
    | nlohmann/json `json` | accept | 370 | 883 | 2,441 | 39,142 | 1.3 |
    | sonic-rs (Rust) | IgnoredAny | 501 | 970 | 2,249 | 54,369 | 1.8 |
    | Boost.JSON | SAX, SAX (numbers: none) | 683 | 913 | 1,642 | 57,932 | 2.9 |
    | yyjson | insitu (copy), read, read (raw numbers) | 393 | 930 | 2,140 | 122,230 | 1.6 |
    | simdjson | DOM | 297 | 687 | 3,165 | 111,631 | 1.7 |
    | sonic-cpp | Document [U] | – (U 404) | – (U 923) | – (U 3,216) | – (U 93,142) | – (U 1.7) |
    | serde_json (Rust) | IgnoredAny [U], from_utf8 + IgnoredAny | 624 (U 484) | 1,440 (U 1,370) | 2,406 (U 2,314) | 64,720 (U 58,247) | 2.4 (U 1.9) |
    | Glaze | validate_json | 705 | 1,971 | 2,532 | 74,805 | 2.5 |
    | simd-json (Rust) | tape (copy) | 567 | 1,430 | 4,359 | 207,551 | 2.9 |
    | RapidJSON | SAX (default precision) (no encoding check) [U], SAX (string stream) (no encoding check) [U], SAX (string stream, default precision), insitu (copy), insitu (copy) (no encoding check) [U] | 1,215 (U 1,052) | 1,550 (U 1,427) | 3,625 | 125,139 (U 104,342) | 4.9 (U 3.2) |

    **sum**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | simdjson | On-Demand | 344 | 809 | 3,405 | 90,960 | 1.9 |
    | **nlohmann/json `json_document`** | parse | 384 | 1,066 | 3,526 | 88,527 | 1.9 |
    | nlohmann/json `json` | sax | 533 | 1,113 | 4,134 | 66,403 | 2.3 |
    | sonic-rs (Rust) | visitor | 501 | 1,123 | 4,397 | 59,583 | 2.5 |
    | sonic-cpp | Document [U] | – (U 458) | – (U 1,120) | – (U 3,887) | – (U 107,494) | – (U 2.0) |
    | yyjson | insitu (copy), read | 445 | 1,093 | 3,948 | 133,860 | 1.9 |
    | Boost.JSON | SAX | 690 | 956 | 5,762 | 62,051 | 2.9 |
    | simd-json (Rust) | visitor (copy) | 681 | 1,650 | 5,083 | 210,185 | 3.5 |
    | serde_json (Rust) | visitor | 1,311 | 2,288 | 7,127 | 129,497 | 4.6 |
    | RapidJSON | SAX (string stream), SAX (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,256 (U 1,099) | 1,713 (U 1,635) | 9,547 (U 9,105) | 127,564 (U 113,500) | 5.1 (U 3.4) |
    | Glaze | generic (double) [P], generic (double, strict), lazy_json [P] | 2,317 | 4,068 | 10,333 | 237,723 | 8.3 (P 6.3) |

    **select**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse | 325 | 863 | 1,302 | 87,940 | 1.6 |
    | yyjson | insitu (copy), read, read (raw numbers) | 402 | 954 | 2,127 | 140,491 | 1.7 |
    | sonic-rs (Rust) | structs | 504 | 1,033 | 2,328 | 90,486 | 2.0 |
    | simdjson | DOM, On-Demand (key selectors) [P], On-Demand [P] | 311 (P 178) | 698 (P 494) | 3,141 (P 674) | 130,228 (P 48,492) | 1.9 (P 1.1) |
    | sonic-cpp | Document [U] | – (U 408) | – (U 942) | – (U 3,166) | – (U 110,763) | – (U 1.8) |
    | Glaze | structs (validate_skipped), structs [P] | 608 (P 345) | 1,978 (P 401) | 2,521 (P 415) | 90,807 (P 67,456) | 2.1 (P 1.5) |
    | serde_json (Rust) | from_utf8 + structs, structs [U] | 701 | 1,532 | 2,529 (U 2,402) | 107,316 | 3.0 |
    | Boost.JSON | parse, parse_into structs | 883 | 1,286 | 6,690 | 101,286 | 3.6 |
    | simd-json (Rust) | structs (copy) | 679 | 1,731 | 5,144 | 239,164 | 3.5 |
    | RapidJSON | Document (string stream), Document (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,217 (U 1,056) | 1,807 | 9,688 | 152,275 | 5.0 (U 3.5) |
    | nlohmann/json `json` | parse, structs (from_json) | 2,984 | 4,548 | 9,124 | 383,108 | 15.2 |

    **edit**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | editable, editable (source numbers) [N] | 538 | 1,214 | 5,640 (N 2,140) | 193,024 | 3.1 |
    | sonic-cpp | Document [U] | – (U 620) | – (U 1,426) | – (U 8,466) | – (U 181,035) | – (U 3.3) |
    | yyjson | insitu (copy) + mut copy, mut copy | 786 | 1,642 | 7,599 | 303,303 | 3.8 |
    | sonic-rs (Rust) | Value | 1,197 | 2,389 | 7,744 | 390,952 | 6.9 |
    | Boost.JSON | parse | 1,859 | 2,513 | 12,765 | 348,703 | 8.8 |
    | RapidJSON | Document (string stream), Document (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,896 (U 1,749) | 2,754 | 19,359 | 269,071 (U 259,148) | 9.1 (U 7.5) |
    | simd-json (Rust) | borrowed (copy), owned (copy) | 1,862 | 4,194 | 14,896 | 391,369 | 9.0 |
    | nlohmann/json `json` | ordered_json, parse | 2,535 | 4,484 | 13,526 | 635,912 | 12.4 |
    | Glaze | generic (strict), generic [P] | 3,364 | 6,036 | 21,592 | 652,302 (P 631,009) | 15.6 |
    | serde_json (Rust) | Value | 4,042 | 6,586 | 16,631 | 632,766 | 17.6 |

    **minify**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse + dump, parse + dump (source numbers) [N] | 478 | 1,152 | 5,209 (N 2,150) | 152,631 (N 145,664) | 2.6 (N 2.4) |
    | yyjson | insitu (copy) + write, read (raw numbers) + write [N], read + write | 610 | 1,277 (N 1,221) | 6,630 (N 2,860) | 199,086 | 3.0 |
    | sonic-cpp | Document + Serialize [U] | – (U 636) | – (U 1,498) | – (U 8,354) | – (U 173,180) | – (U 3.3) |
    | simdjson | DOM + to_string, minify [P] | 666 (P 93.3) | 1,354 (P 279) | 8,606 (P 314) | 280,739 (P 46,006) | 3.9 (P 0.5) |
    | sonic-rs (Rust) | Value | 1,000 | 2,097 | 7,795 | 215,280 | 5.4 |
    | Boost.JSON | parse + serialize | 1,783 | 2,498 | 12,367 | 329,300 | 8.9 |
    | RapidJSON | SAX to Writer (raw numbers) [N], SAX to Writer (string stream), SAX to Writer (string stream) (no encoding check) [U] | 1,851 (U 1,710) | 2,429 | 18,810 (N 14,205) | 229,769 | 9.0 (U 6.7) |
    | simd-json (Rust) | borrowed (copy) | 1,889 | 4,196 | 15,716 | 414,377 | 9.2 |
    | nlohmann/json `json` | parse + dump | 3,369 | 5,399 | 13,402 | 493,302 | 18.4 |
    | Glaze | generic (strict), minify_json [P] | 3,243 (P 417) | 6,175 (P 1,299) | 20,961 (P 2,699) | 451,368 (P 93,794) | 15.3 (P 2.1) |
    | serde_json (Rust) | Value | 4,012 | 6,583 | 17,306 | 509,702 | 16.5 |

    **write**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | dump, dump (source numbers) [N] | 154 (N 139) | 251 (N 229) | 3,946 (N 831) | 64,776 | 0.9 (N 0.8) |
    | yyjson | write | 185 | 318 | 3,330 | 67,531 | 1.3 |
    | sonic-cpp | Serialize | 258 | 508 | 5,077 | 72,262 | 1.6 |
    | nlohmann/json `json` | dump | 413 | 611 | 3,905 | 113,990 | 1.8 |
    | simdjson | to_string | 346 | 610 | 5,580 | 158,670 | 1.8 |
    | Glaze | generic | 377 | 730 | 4,050 | 129,720 | 2.0 |
    | sonic-rs (Rust) | Value | 434 | 927 | 3,987 | 109,176 | 2.8 |
    | Boost.JSON | serialize | 451 | 832 | 5,570 | 138,780 | 2.4 |
    | simd-json (Rust) | borrowed | 582 | 800 | 5,147 | 122,623 | 2.8 |
    | serde_json (Rust) | Value | 550 | 887 | 4,005 | 134,163 | 3.3 |
    | RapidJSON | Writer | 638 | 984 | 8,886 | 131,435 | 3.9 |

??? info "Times in µs on x86-64 with GCC 13.4"

    **validate**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | accept | 267 | 664 | 986 | 34,874 | 1.2 |
    | nlohmann/json `json` | accept | 312 | 686 | 2,345 | 38,948 | 1.3 |
    | sonic-rs (Rust) | IgnoredAny | 501 | 970 | 2,249 | 54,369 | 1.8 |
    | Glaze | validate_json | 584 | 1,402 | 1,837 | 71,382 | 2.3 |
    | Boost.JSON | SAX, SAX (numbers: none) | 730 | 934 | 1,637 | 60,745 | 3.2 |
    | yyjson | insitu (copy), read, read (raw numbers) | 394 | 984 | 2,222 | 128,528 | 1.6 |
    | simdjson | DOM | 309 | 737 | 3,183 | 115,296 | 1.8 |
    | sonic-cpp | Document [U] | – (U 409) | – (U 1,025) | – (U 3,561) | – (U 96,607) | – (U 1.5) |
    | serde_json (Rust) | IgnoredAny [U], from_utf8 + IgnoredAny | 624 (U 484) | 1,440 (U 1,370) | 2,406 (U 2,314) | 64,720 (U 58,247) | 2.4 (U 1.9) |
    | simd-json (Rust) | tape (copy) | 567 | 1,430 | 4,359 | 207,551 | 2.9 |
    | RapidJSON | SAX (default precision) (no encoding check) [U], SAX (string stream) (no encoding check) [U], SAX (string stream, default precision), SAX (string stream, default precision) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,201 (U 1,033) | 1,931 (U 1,487) | 4,114 (U 3,966) | 145,137 (U 127,587) | 4.8 (U 3.2) |

    **sum**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | simdjson | On-Demand | 356 | 819 | 3,291 | 94,267 | 1.9 |
    | **nlohmann/json `json_document`** | parse | 387 | 1,036 | 3,704 | 89,477 | 1.9 |
    | nlohmann/json `json` | sax | 451 | 941 | 3,816 | 64,406 | 2.3 |
    | sonic-rs (Rust) | visitor | 501 | 1,123 | 4,397 | 59,583 | 2.5 |
    | sonic-cpp | Document [U] | – (U 459) | – (U 1,209) | – (U 4,247) | – (U 103,731) | – (U 1.9) |
    | yyjson | insitu (copy), read | 443 | 1,146 | 5,974 | 129,054 | 2.0 |
    | Boost.JSON | SAX | 746 | 1,025 | 5,370 | 63,333 | 3.3 |
    | simd-json (Rust) | visitor (copy) | 681 | 1,650 | 5,083 | 210,185 | 3.5 |
    | serde_json (Rust) | visitor | 1,311 | 2,288 | 7,127 | 129,497 | 4.6 |
    | RapidJSON | SAX (no encoding check) [U], SAX (string stream), SAX (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,256 (U 1,085) | 2,114 (U 1,750) | 11,059 | 155,532 (U 128,734) | 5.2 (U 3.5) |
    | Glaze | generic (double, strict), lazy_json [P] | 2,341 | 4,037 | 10,434 | 249,828 (P 219,119) | 8.5 (P 5.9) |

    **select**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse, structs (from_json) | 329 | 855 | 1,360 | 90,597 | 1.6 |
    | yyjson | insitu (copy), read, read (raw numbers) | 397 | 994 | 2,228 | 140,073 | 1.8 |
    | sonic-rs (Rust) | structs | 504 | 1,033 | 2,328 | 90,486 | 2.0 |
    | simdjson | DOM, On-Demand (key selectors) [P], On-Demand [P] | 323 (P 186) | 748 (P 508) | 3,189 (P 707) | 126,288 (P 50,215) | 2.0 (P 1.2) |
    | Glaze | structs (validate_skipped), structs [P] | 523 (P 338) | 1,473 (P 406) | 1,853 (P 434) | 89,506 (P 66,029) | 1.9 (P 1.4) |
    | sonic-cpp | Document [U] | – (U 412) | – (U 1,044) | – (U 3,632) | – (U 106,188) | – (U 1.7) |
    | serde_json (Rust) | from_utf8 + structs, structs [U] | 701 | 1,532 | 2,529 (U 2,402) | 107,316 | 3.0 |
    | simd-json (Rust) | structs (copy) | 679 | 1,731 | 5,144 | 239,164 | 3.5 |
    | Boost.JSON | parse, parse_into structs | 899 | 1,353 | 7,011 | 100,039 | 3.9 |
    | RapidJSON | Document (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,207 (U 1,037) | 1,947 (U 1,847) | 11,910 | 164,386 (U 147,489) | 5.0 (U 3.4) |
    | nlohmann/json `json` | parse, structs (from_json) | 3,032 | 4,466 | 9,085 | 376,812 | 15.7 |

    **edit**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | editable, editable (source numbers) [N] | 530 | 1,209 | 5,792 (N 2,621) | 193,925 | 3.1 |
    | sonic-cpp | Document [U] | – (U 632) | – (U 1,583) | – (U 8,734) | – (U 184,592) | – (U 3.4) |
    | yyjson | insitu (copy) + mut copy, mut copy | 841 | 1,719 | 9,803 | 309,935 | 3.8 |
    | sonic-rs (Rust) | Value | 1,197 | 2,389 | 7,744 | 390,952 | 6.9 |
    | Boost.JSON | parse | 1,889 | 2,952 | 13,537 | 346,542 | 9.6 |
    | RapidJSON | Document (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,920 (U 1,747) | 2,977 (U 2,823) | 21,152 | 293,851 (U 280,165) | 9.3 (U 7.6) |
    | simd-json (Rust) | borrowed (copy), owned (copy) | 1,862 | 4,194 | 14,896 | 391,369 | 9.0 |
    | nlohmann/json `json` | ordered_json, parse | 2,503 | 4,414 | 13,479 | 622,816 | 12.7 |
    | Glaze | generic (strict), generic [P] | 3,474 | 6,531 (P 6,302) | 23,193 | 673,526 | 16.5 (P 16.0) |
    | serde_json (Rust) | Value | 4,042 | 6,586 | 16,631 | 632,766 | 17.6 |

    **minify**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse + dump, parse + dump (source numbers) [N] | 475 | 1,102 | 5,414 (N 2,372) | 144,877 | 2.5 |
    | yyjson | insitu (copy) + write, read (raw numbers) + write [N], read + write | 600 | 1,316 (N 1,264) | 9,151 (N 2,994) | 201,645 | 3.1 |
    | sonic-cpp | Document + Serialize [U] | – (U 647) | – (U 1,563) | – (U 8,917) | – (U 176,625) | – (U 3.4) |
    | simdjson | DOM + to_string, minify [P] | 689 (P 122) | 1,394 (P 336) | 8,457 (P 426) | 292,576 (P 49,731) | 4.1 (P 0.6) |
    | sonic-rs (Rust) | Value | 1,000 | 2,097 | 7,795 | 215,280 | 5.4 |
    | Boost.JSON | parse + serialize | 1,907 | 2,950 | 13,662 | 342,183 | 10.2 |
    | simd-json (Rust) | borrowed (copy) | 1,889 | 4,196 | 15,716 | 414,377 | 9.2 |
    | RapidJSON | SAX to Writer, SAX to Writer (raw numbers) (no encoding check) [U N], SAX to Writer (string stream), SAX to Writer (string stream) (no encoding check) [U] | 2,746 (U 1,824) | 3,162 (U 2,672) | 21,674 (U N 15,166) | 381,832 (U 259,100) | 15.6 (U 8.5) |
    | nlohmann/json `json` | parse + dump | 3,417 | 5,153 | 13,425 | 504,511 | 18.5 |
    | Glaze | generic (strict), minify_json [P] | 3,359 (P 417) | 6,437 (P 1,116) | 23,896 (P 2,113) | 480,814 (P 97,812) | 15.9 (P 1.9) |
    | serde_json (Rust) | Value | 4,012 | 6,583 | 17,306 | 509,702 | 16.5 |

    **write**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | dump, dump (source numbers) [N] | 152 (N 147) | 260 | 3,811 (N 997) | 72,196 | 0.9 |
    | yyjson | write | 180 | 325 | 3,548 | 71,044 | 1.2 |
    | sonic-cpp | Serialize | 268 | 543 | 5,057 | 75,734 | 1.7 |
    | Glaze | generic | 336 | 682 | 3,750 | 133,730 | 1.8 |
    | nlohmann/json `json` | dump | 413 | 617 | 4,036 | 124,865 | 1.9 |
    | simdjson | to_string | 360 | 636 | 5,363 | 169,032 | 1.9 |
    | sonic-rs (Rust) | Value | 434 | 927 | 3,987 | 109,176 | 2.8 |
    | simd-json (Rust) | borrowed | 582 | 800 | 5,147 | 122,623 | 2.8 |
    | Boost.JSON | serialize | 474 | 1,003 | 6,012 | 148,120 | 2.5 |
    | serde_json (Rust) | Value | 550 | 887 | 4,005 | 134,163 | 3.3 |
    | RapidJSON | Writer | 661 | 1,015 | 8,980 | 136,957 | 4.1 |

??? info "Times in µs on x86-64 with Clang 23"

    **validate**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | accept | 250 | 509 | 1,032 | 34,454 | 1.1 |
    | nlohmann/json `json` | accept | 335 | 711 | 2,018 | 39,513 | 1.4 |
    | sonic-rs (Rust) | IgnoredAny | 501 | 970 | 2,249 | 54,369 | 1.8 |
    | Boost.JSON | SAX, SAX (numbers: none) | 570 | 903 | 1,678 | 55,087 | 2.3 |
    | simdjson | DOM | 302 | 721 | 3,202 | 116,859 | 1.7 |
    | yyjson | insitu (copy), read, read (raw numbers) | 383 | 887 | 2,572 | 123,640 | 1.6 |
    | sonic-cpp | Document [U] | – (U 451) | – (U 998) | – (U 3,031) | – (U 95,823) | – (U 1.8) |
    | Glaze | validate_json | 594 | 1,230 | 2,139 | 73,235 | 2.5 |
    | serde_json (Rust) | IgnoredAny [U], from_utf8 + IgnoredAny | 624 (U 484) | 1,440 (U 1,370) | 2,406 (U 2,314) | 64,720 (U 58,247) | 2.4 (U 1.9) |
    | simd-json (Rust) | tape (copy) | 567 | 1,430 | 4,359 | 207,551 | 2.9 |
    | RapidJSON | SAX (default precision), SAX (default precision) (no encoding check) [U], SAX (string stream, default precision), SAX (string stream, default precision) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,798 (U 1,173) | 1,944 (U 1,504) | 4,019 | 232,684 (U 128,516) | 8.1 (U 4.1) |

    **sum**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse | 366 | 941 | 3,680 | 86,966 | 1.8 |
    | nlohmann/json `json` | sax | 431 | 914 | 3,824 | 60,439 | 2.1 |
    | simdjson | DOM, On-Demand | 391 | 969 | 4,121 | 116,855 | 2.2 |
    | sonic-rs (Rust) | visitor | 501 | 1,123 | 4,397 | 59,583 | 2.5 |
    | yyjson | insitu (copy), read | 436 | 1,048 | 3,454 | 133,577 | 1.9 |
    | sonic-cpp | Document [U] | – (U 504) | – (U 1,176) | – (U 3,701) | – (U 104,509) | – (U 2.1) |
    | Boost.JSON | SAX | 580 | 928 | 5,715 | 55,874 | 2.3 |
    | simd-json (Rust) | visitor (copy) | 681 | 1,650 | 5,083 | 210,185 | 3.5 |
    | serde_json (Rust) | visitor | 1,311 | 2,288 | 7,127 | 129,497 | 4.6 |
    | RapidJSON | SAX, SAX (no encoding check) [U], SAX (string stream), SAX (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,846 (U 1,229) | 2,176 (U 1,761) | 10,561 | 239,499 (U 131,510) | 8.4 (U 4.3) |
    | Glaze | generic (double) [P], generic (double, strict), lazy_json [P] | 2,374 | 3,982 | 11,930 | 261,204 (P 198,036) | 9.0 (P 5.6) |

    **select**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse, structs (from_json) | 316 | 783 | 1,368 | 91,736 | 1.6 |
    | yyjson | insitu (copy), read (raw numbers) | 386 | 891 | 2,572 | 135,813 | 1.7 |
    | sonic-rs (Rust) | structs | 504 | 1,033 | 2,328 | 90,486 | 2.0 |
    | simdjson | DOM, On-Demand (key selectors) [P], On-Demand [P] | 318 (P 182) | 728 (P 494) | 3,213 (P 692) | 129,986 (P 50,660) | 2.0 (P 1.1) |
    | Glaze | structs (validate_skipped), structs [P] | 542 (P 337) | 1,369 (P 416) | 1,846 (P 447) | 83,907 (P 68,455) | 2.2 (P 1.6) |
    | sonic-cpp | Document [U] | – (U 454) | – (U 1,015) | – (U 3,025) | – (U 112,621) | – (U 2.0) |
    | serde_json (Rust) | from_utf8 + structs, structs [U] | 701 | 1,532 | 2,529 (U 2,402) | 107,316 | 3.0 |
    | Boost.JSON | parse, parse_into structs | 760 | 1,388 | 7,026 | 97,008 | 3.2 |
    | simd-json (Rust) | structs (copy) | 679 | 1,731 | 5,144 | 239,164 | 3.5 |
    | RapidJSON | Document (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 1,806 (U 1,184) | 2,303 (U 1,929) | 11,395 | 257,762 (U 171,716) | 8.7 (U 4.3) |
    | nlohmann/json `json` | parse, structs (from_json) | 3,181 | 4,583 | 9,599 | 405,734 | 18.9 |

    **edit**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | editable, editable (source numbers) [N] | 519 | 1,152 | 5,671 (N 2,502) | 195,716 | 3.0 |
    | sonic-cpp | Document [U] | – (U 642) | – (U 1,497) | – (U 8,153) | – (U 184,321) | – (U 3.3) |
    | yyjson | insitu (copy) + mut copy, mut copy | 833 | 1,674 | 7,249 | 316,652 | 4.2 |
    | sonic-rs (Rust) | Value | 1,197 | 2,389 | 7,744 | 390,952 | 6.9 |
    | Boost.JSON | parse | 1,716 | 2,578 | 13,427 | 354,510 | 8.9 |
    | simd-json (Rust) | borrowed (copy), owned (copy) | 1,862 | 4,194 | 14,896 | 391,369 | 9.0 |
    | RapidJSON | Document (string stream) (no encoding check) [U], insitu (copy), insitu (copy) (no encoding check) [U] | 2,478 (U 1,842) | 3,261 (U 2,887) | 21,686 | 378,727 (U 294,727) | 13.1 (U 8.3) |
    | nlohmann/json `json` | ordered_json, parse | 2,452 | 4,402 | 14,765 | 646,489 | 12.6 |
    | serde_json (Rust) | Value | 4,042 | 6,586 | 16,631 | 632,766 | 17.6 |
    | Glaze | generic (strict), generic [P] | 3,896 | 7,671 | 28,104 (P 27,111) | 723,675 | 20.2 |

    **minify**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | parse + dump, parse + dump (source numbers) [N] | 472 | 1,055 | 5,041 (N 2,363) | 149,143 | 2.5 |
    | yyjson | read (raw numbers) + write [N], read + write | 626 | 1,261 | 6,179 (N 3,426) | 200,886 | 3.3 |
    | sonic-cpp | Document + Serialize [U] | – (U 655) | – (U 1,474) | – (U 7,856) | – (U 169,992) | – (U 3.5) |
    | simdjson | DOM + to_string, minify [P] | 706 (P 99.0) | 1,411 (P 270) | 8,125 (P 329) | 270,332 (P 42,546) | 4.3 (P 0.5) |
    | sonic-rs (Rust) | Value | 1,000 | 2,097 | 7,795 | 215,280 | 5.4 |
    | Boost.JSON | parse + serialize | 1,722 | 2,573 | 12,678 | 330,878 | 9.0 |
    | simd-json (Rust) | borrowed (copy) | 1,889 | 4,196 | 15,716 | 414,377 | 9.2 |
    | RapidJSON | Document + Writer, SAX to Writer, SAX to Writer (no encoding check) [U], SAX to Writer (raw numbers) (no encoding check) [U N], SAX to Writer (string stream), SAX to Writer (string stream) (no encoding check) [U] | 2,456 (U 1,794) | 2,864 (U 2,444) | 21,753 (U N 14,707) | 338,985 (U 252,656) | 13.6 (U 7.5) |
    | nlohmann/json `json` | parse + dump | 3,525 | 5,178 | 14,024 | 506,705 | 20.6 |
    | serde_json (Rust) | Value | 4,012 | 6,583 | 17,306 | 509,702 | 16.5 |
    | Glaze | generic (strict), minify_json [P] | 3,801 (P 422) | 7,482 (P 1,051) | 26,932 (P 2,140) | 544,342 (P 87,842) | 19.2 (P 2.1) |

    **write**

    | library | variant | `twitter.json` | `citm_catalog.json` | `canada.json` | `jeopardy.json` | one status (2.5 KB) |
    | --- | --- | --: | --: | --: | --: | --: |
    | **nlohmann/json `json_document`** | dump, dump (source numbers) [N] | 158 (N 153) | 279 | 3,637 (N 982) | 67,366 | 0.9 |
    | yyjson | write | 216 | 367 | 3,366 | 73,272 | 1.4 |
    | sonic-cpp | Serialize | 228 | 474 | 4,766 | 66,619 | 1.3 |
    | nlohmann/json `json` | dump | 438 | 599 | 4,458 | 116,318 | 1.9 |
    | Glaze | generic, generic (strict) | 396 | 725 | 4,107 | 132,573 | 2.1 |
    | simdjson | to_string | 382 | 661 | 4,787 | 162,220 | 2.1 |
    | sonic-rs (Rust) | Value | 434 | 927 | 3,987 | 109,176 | 2.8 |
    | Boost.JSON | serialize | 478 | 913 | 5,610 | 141,994 | 2.6 |
    | simd-json (Rust) | borrowed | 582 | 800 | 5,147 | 122,623 | 2.8 |
    | serde_json (Rust) | Value | 550 | 887 | 4,005 | 134,163 | 3.3 |
    | RapidJSON | Writer | 633 | 960 | 9,388 | 127,319 | 3.8 |

### F. Behavior changes

Visible changes that came with the speed:

- **Float output** ([#5634][5634]). Żmij writes the shortest decimal that reads back as the same `double`, and the
  closest one if there are several. Of one million random `double` bit patterns, 1,425 (0.14%) are now written
  differently: 810 with fewer digits (`5.3165205877497296e+16` becomes `5.31652058774973e+16`), 615 with the same number
  of digits but the closer ones. They all read back as the same `double`, and none of one million short decimals
  changes. In `canada.json`, 69 of the 111,126 numbers come out differently.
- **Error positions** ([#5283][5283]). The column reported after a number at the end of a line is now correct; the fast
  paths otherwise report the same byte, line, and column as the byte path, checked on 481,000 documents.
- **SAX float text** ([#5852][5852]). The built-in handlers behind `parse()` and `accept()` get an empty string as the
  text of a float token. A user-written SAX handler still gets the token's text.
- **`FILE*` locking** ([#5828][5828]). The lock is taken once and held for the whole parse instead of once per byte. The
  documentation mentions it, and an opt-out macro restores the old behavior.

### G. How we measured

**What is compared.** "3.12.0" is the released single header and "3.13.0" the released one. Both are compiled from the
*same* benchmark source, the Google Benchmark suite in
[`tests/benchmarks`](https://github.com/nlohmann/json/tree/develop/tests/benchmarks), with the BON8 benchmarks removed
because 3.12.0 has no BON8.

| | |
| --- | --- |
| machine | Apple M1 Max laptop on AC power, macOS 27.0.1 |
| compiler | Apple clang 21, libc++ |
| flags | `-O3 -flto -DNDEBUG`, the compiler's default standard, C++14 |
| suite | 3 rounds × 4 repetitions per version, random interleaving, each round of a version started only when the load average was below 4 and repeated when it rose above 5 while running; the rounds of a version differed by less than 1% overall; the median of all 12 |
| noise | the coefficient of variation was 3% or less for 180 of the 182 rows with 3.12.0 and 179 with 3.13.0; the largest was 5.4% (`Iterate/twitter` with 3.13.0), not counting two disturbed runs: two repetitions of a 0.4 µs benchmark with 3.12.0 that took 2.4× as long, and one of a 46 ms one with 3.13.0 that took 1.4× as long |
| inputs | the files of [Appendix A](#a-test-files), and number-heavy files |
| Intel check | the suite again on a MacBook Pro (15-inch, 2016) with an Intel Core i7-6920HQ (Skylake, 4 cores), macOS 12.0.1, Apple clang 13, the same flags with C++11; started below a load of 3, repeated above 4; the first round of each version dropped (3.12.0's was 4.7% slower than the others); the coefficient of variation was 3% or less for 120 rows with 3.12.0 and 161 of 234 with 3.13.0, so single rows are less reliable than on the M1 Max; geometric mean 3.07×, and two rows below 1×: copying `citm_catalog.json` without destroying the copy (0.93×) and `==` of it and a copy (0.95×), both in each round |

<p class="nj-table-caption" markdown>Setup of the Google Benchmark comparison of 3.12.0 and 3.13.0.</p>

**The other measurements.** The timeline is
[`tests/benchmarks/history`](https://github.com/nlohmann/json/tree/develop/tests/benchmarks/history): one program,
compiled against `single_include` of 3.12.0, of each of the 358 commits on `develop` up to November 7 that changed
`json.hpp` or `json_view.hpp` since, and of 3.13.0 (C++17, `-O3`, no LTO), 4 rounds in random order, median of the
rounds (the mean of the two middle ones). Two commits that don't compile on their own are left out. The commits up to
October 27 were run on October 27, those up to November 2 on November 3, and the later ones and 3.13.0 on November 7,
each time together with twelve of the earlier commits as a check: per workload, their median moved by 1.5% or less
(3% for `json_view`'s parse of `canada.json`, which only three of them have). The algorithmic fixes come from small
extra programs (C++17, `-O3`, median of 3 interleaved runs). The comparison with other libraries is described in
[Appendix E](#e-comparison-with-other-libraries).

**Compile times.** The two programs of [The price](#the-price), each compiled as one translation unit with `-std=c++20`
(modules need it) and `-O0` or `-O2`, with Apple clang 21 and Homebrew GCC 16.2 on the M1 Max. The time is the CPU time
(user plus system) of the compiler process, the median of 5 rounds in which all 40 compilations ran in a random order.
The slowest of the 5 runs was within 14% of the fastest for every program and every build of the precompiled header or
the module. Every variant was also linked and run once, with the same output from all of them.

| build | program | 3.12.0 | 3.13.0 | 3.13.0, PCH | 3.13.0, module |
| --- | --- | --: | --: | --: | --: |
| Apple clang `-O0` | `count_numbers` | 831 | 1,131 | 639 | 790 |
|  | `server_config` | 963 | 1,313 | 774 | 1,037 |
| Apple clang `-O2` | `count_numbers` | 1,328 | 1,898 | 1,312 | 1,491 |
|  | `server_config` | 1,584 | 2,251 | 1,779 | 1,926 |
| GCC 16 `-O0` | `count_numbers` | 1,417 | 2,385 | 1,593 | 1,604 |
|  | `server_config` | 1,878 | 2,820 | 2,152 | 2,180 |
| GCC 16 `-O2` | `count_numbers` | 2,159 | 3,465 | 2,765 | 2,740 |
|  | `server_config` | 2,878 | 4,388 | 3,722 | 3,774 |

<p class="nj-table-caption" markdown>Compile time in milliseconds of the two programs in [The price](#the-price) (CPU
time of the compiler, median of 5 runs). Building the precompiled header took 917 and 879 ms with Apple clang (`-O0`,
`-O2`) and 2,306 and 2,264 ms with GCC; building the module took 1,399 and 1,433 ms or 2,339 and 2,325 ms.</p>

??? example "The programs and the build commands"

    ```cpp
    // Reads a JSON file and adds up all of its numbers (the "sum" use case of the benchmark).
    #include <cstddef>
    #include <fstream>
    #include <iostream>
    #ifdef USE_MODULE
    import nlohmann.json;
    #else
    #include <nlohmann/json.hpp>
    #endif

    using nlohmann::json;

    static double sum_numbers(const json& j)
    {
        switch (j.type())
        {
            case json::value_t::array:
            case json::value_t::object:
            {
                double sum = 0;
                for (const auto& element : j)
                {
                    sum += sum_numbers(element);
                }
                return sum;
            }
            case json::value_t::number_integer:
            case json::value_t::number_unsigned:
            case json::value_t::number_float:
                return j.get<double>();
            default:
                return 0;
        }
    }

    int main(int argc, char* argv[])
    {
        if (argc != 2)
        {
            return 1;
        }
        std::ifstream in(argv[1]);
        const json j = json::parse(in);
        std::cout << sum_numbers(j) << '\n';
    }
    ```

    <p class="nj-code-caption" markdown>`count_numbers.cpp`.</p>

    ```cpp
    // Reads a configuration file into a struct, changes it, and writes it back indented.
    #include <fstream>
    #include <iostream>
    #include <string>
    #include <vector>
    #ifdef USE_MODULE
    import nlohmann.json;
    #else
    #include <nlohmann/json.hpp>
    #endif

    using nlohmann::json;

    struct server_config
    {
        std::string host;
        int port = 0;
        double timeout = 0;
        std::vector<std::string> tags;
    };

    void to_json(json& j, const server_config& c)
    {
        j = json{{"host", c.host}, {"port", c.port}, {"timeout", c.timeout}, {"tags", c.tags}};
    }

    void from_json(const json& j, server_config& c)
    {
        j.at("host").get_to(c.host);
        j.at("port").get_to(c.port);
        j.at("timeout").get_to(c.timeout);
        j.at("tags").get_to(c.tags);
    }

    int main(int argc, char* argv[])
    {
        if (argc != 3)
        {
            return 1;
        }
        std::ifstream in(argv[1]);
        auto config = json::parse(in).get<server_config>();
        config.port += 1;
        config.tags.push_back("updated");
        std::ofstream(argv[2]) << json(config).dump(2) << '\n';
    }
    ```

    <p class="nj-code-caption" markdown>`server_config.cpp`.</p>

    ```sh
    # Apple clang: the precompiled header (pch.hpp contains only #include <nlohmann/json.hpp>) ...
    clang++ -std=c++20 -O2 -I single_include -x c++-header pch.hpp -o pch.hpp.pch
    clang++ -std=c++20 -O2 -I single_include -include-pch pch.hpp.pch -c count_numbers.cpp
    # ... and the module
    clang++ -std=c++20 -O2 -fcxx-modules -I single_include -c -x c++-module src/modules/json.cppm \
        -fmodule-output=nlohmann.json.pcm -o json_mod.o
    clang++ -std=c++20 -O2 -fcxx-modules -fmodule-file=nlohmann.json=nlohmann.json.pcm -DUSE_MODULE \
        -c count_numbers.cpp

    # GCC 16 (Homebrew on macOS, add --sysroot=$(xcrun --show-sdk-path))
    g++-16 -std=c++20 -O2 -I single_include -x c++-header pch.hpp -o pch.hpp.gch
    g++-16 -std=c++20 -O2 -I single_include -include pch.hpp -Winvalid-pch -c count_numbers.cpp
    g++-16 -std=c++20 -O2 -fmodules -I single_include -c src/modules/json.cppm -o json_mod.o
    g++-16 -std=c++20 -O2 -fmodules -DUSE_MODULE -c count_numbers.cpp
    ```

    <p class="nj-code-caption" markdown>The commands for one program at `-O2`; the module variants are linked with
    `json_mod.o`.</p>

**What we did not measure.** The timeline and the algorithmic fixes ran on one Apple silicon laptop with Clang, the
suite also on an Intel laptop with Clang. The comparison with other libraries also ran on an x86-64 server with GCC
16.2, GCC 13, and Clang 23, and on the Mac with GCC 16.2 and Clang 23 as a check. That server is a virtual machine with
8 cores that present themselves as Haswell; its timings show the penalty of the microcode fix for Intel's JCC erratum,
which Haswell doesn't have, so the real CPU is probably a later one. It shares its cores with other work, so its
differences of a few percent are noise. The theme sections quote x86-64 numbers where a pull request measured them,
mostly with GCC 13 and Clang 18. Expect smaller gains for some workloads on x86-64 with glibc: its `FILE*` locking is
cheaper to begin with, so taking it once per parse gains less, its allocator behaves differently, and fresh output
memory costs more page faults. We did not measure on Windows, and we did not measure binary size or memory use.

### H. Pull requests by theme

- <a class="nj-theme" href="#theme-1" title="theme 1">1</a> **Specialize for each input source:** contiguous input
  [#5283][5283]; streams and `FILE*` [#5828][5828], [#5884][5884]; the buffer of a `FILE` [#6030][6030]; iterator
  pairs [#6029][6029]; one loop for parser and lexer [#6031][6031]; binary strings in bulk [#5233][5233]; sized
  sentinels [#5268][5268].
- <a class="nj-theme" href="#theme-2" title="theme 2">2</a> **Work on words, not bytes:** word-at-a-time strings, UTF-8
  runs, and digits [#5283][5283], [#5738][5738], [#5851][5851]; indentation [#5810][5810]; `dump()` runs [#5285][5285];
  SSE2 and NEON [#5853][5853], [#5628][5628]; `json_document` with `ensure_ascii` [#5879][5879]; short strings
  [#5878][5878], [#5883][5883]; escape table [#5822][5822]; loop shape [#5490][5490]; fraction digits [#5971][5971];
  BSON keys [#5968][5968]; UTF-8 checks of binary strings [#5982][5982]; one SIMD macro set [#5921][5921]; fewer
  operations per word and vector [#6033][6033].
- <a class="nj-theme" href="#theme-3" title="theme 3">3</a> **Own the number conversions:** Eisel-Lemire [#5617][5617];
  long numbers [#5738][5738]; one pass over the digits [#5851][5851]; Żmij [#5634][5634]; long integers in `dump()`
  [#5964][5964]; MSVC intrinsics for the 128-bit multiplication [#5782][5782].
- <a class="nj-theme" href="#theme-4" title="theme 4">4</a> **Don't do unnecessary work:** float token text
  [#5852][5852]; token buffer [#5234][5234], [#5828][5828]; positions on error [#5809][5809]; binary readers' copy
  [#5501][5501]; `ordered_json` growth [#5609][5609]; arrays at their final size [#5882][5882]; moving keys
  [#5458][5458], [#5855][5855]; separator check [#5592][5592]; CBOR keys [#5328][5328]; `accept()` without copies
  [#5978][5978]; runs of scalars in binary arrays [#5975][5975], [#5980][5980], [#5981][5981], [#6008][6008]; BJData
  marker list [#5555][5555]; `from_json()` into containers [#5833][5833]; binary strings without a zero fill
  [#6028][6028].
- <a class="nj-theme" href="#theme-5" title="theme 5">5</a> **Read the assembly:** stack canary [#5854][5854];
  exceptions and inlining [#5838][5838], [#5840][5840], [#5839][5839], [#5836][5836]; aliasing [#5633][5633]; forced
  inlining [#5878][5878]; branch-free selections [#5908][5908]; code size [#5902][5902]; the order of the iterator's
  type tests [#6039][6039].
- <a class="nj-theme" href="#theme-6" title="theme 6">6</a> **Write through a cursor:** write buffer [#5285][5285];
  adapter on the stack [#5449][5449]; binary sinks [#5286][5286]; cursor and runs of numbers [#5824][5824],
  [#5885][5885]; `to_bson()` in one pass [#5979][5979]; a window instead of zeroing the whole capacity [#6020][6020].
- <a class="nj-theme" href="#theme-7" title="theme 7">7</a> **Fix the algorithm first:** `diff()` [#5461][5461]; parse
  callbacks [#5457][5457]; `operator<` [#5390][5390]; `flatten()` [#5834][5834]; `unflatten()` [#5793][5793]; JSON
  Pointer and Patch [#5861][5861], [#5886][5886]; `to_bson()` [#5553][5553]; `JSON_DIAGNOSTICS` [#5832][5832]; bounded
  recursion [#5285][5285], [#5389][5389], [#5547][5547]; destructor [#5762][5762], [#5835][5835].
- <a class="nj-theme" href="#theme-8" title="theme 8">8</a> **Build a different data structure:** `json_document`
  [#5620][5620], [#5627][5627], [#5628][5628], [#5622][5622], [#5908][5908], [#5879][5879]; `accept()` without an index
  [#5970][5970]; reading and indexing [#5888][5888], [#5915][5915], [#5889][5889], [#5890][5890]; editing [#5630][5630],
  [#5919][5919], [#5926][5926].
- **Validation:** guard pages [#5826][5826]; differential fuzzing [#5827][5827]; float checks [#5617][5617],
  [#5908][5908]; mutation checks [#5878][5878].
- **The UTF-8 check that came and went:** [#5185][5185], [#5531][5531], [#5741][5741], [#5746][5746].

### I. Details of the themes

**Eisel-Lemire (theme <a class="nj-theme" href="#theme-3" title="theme 3">3</a>).**
[fast_float](https://github.com/fastfloat/fast_float)'s `compute_float`, which 3.13.0 adapts, works with integers only.
The value is `w · 10^q = w · 5^q · 2^q`, so it normalizes `w` to 64 significant bits, multiplies it with a 128-bit
approximation of `5^q` from a table of 651 entries, and takes the 53 bits of the mantissa plus one rounding bit from the
top of the product. The binary exponent comes from a fixed-point `log2(10)`. If the nine bits below the rounding bit are
all ones, the truncated part of the table entry could still carry into the result; then a second multiplication with the
next 64 bits of `5^q` decides, which happens for about one input in 512. Mushtak and Lemire showed in 2023 that for up
to 19 digits these 128 bits always suffice, so the algorithm needs no fallback. Exact ties between two `double`s, the
only place where rounding half to even matters, can only occur for small exponents, and are handled there. (Clinger's
fast path, by contrast, uses the floating-point unit and assumes the default rounding mode.)

Numbers with more than 19 digits are rare in JSON. For them, Eisel-Lemire runs on the first 19 digits, `w`, and on
`w + 1`: the true value lies between the two, so if both give the same `double`, that is the answer. Only if they differ
does fast_float's digit comparison build the exact midpoint between the two candidates as a big integer and compare all
digits with it.

**Żmij's digits (theme <a class="nj-theme" href="#theme-3" title="theme 3">3</a>).** Żmij's digit conversion, by Xiang
JunBo, is the same divide-by-multiplying idea as the parser's, run backwards on all lanes of a word at once:

```cpp
// 12345678 -> the bytes 1, 2, 3, 4, 5, 6, 7, 8 (one digit per byte)
std::uint64_t eight_digit_bytes(std::uint64_t abcdefgh) noexcept
{
    // x / d as (x * (2^k / d + 1)) >> k
    const std::uint64_t abcd = (abcdefgh * (((1ull << 40) / 10000) + 1)) >> 40;
    const std::uint64_t abcd_efgh = abcdefgh + ((1ull << 32) - 10000) * abcd;
    const std::uint64_t ab_ef = ((abcd_efgh * (((1ull << 19) / 100) + 1)) >> 19) & 0x7F0000007Full;
    const std::uint64_t ab_cd_ef_gh = abcd_efgh + ((1ull << 16) - 100) * ab_ef;
    const std::uint64_t a_c_e_g =
        ((ab_cd_ef_gh * (((1ull << 10) / 10) + 1)) >> 10) & 0x000F000F000F000Full;
    return ab_cd_ef_gh + ((1ull << 8) - 10) * a_c_e_g;
}
```

<p class="nj-code-caption" markdown>Żmij's conversion of an eight-digit number to one digit per byte, in three steps of
divide-by-multiplying.</p>

`(x · ⌈2^k / d⌉) >> k` is `x / d` for the range that occurs, and `x + (2^w − d) · (x / d)` rewrites `x` as
`(x / d) · 2^w + x mod d`: the quotient moves up into the next lane. Three steps split 8 digits into 4 + 4, 2 + 2 + 2 +
2, and single digits. A zero digit becomes a zero byte, so leading and trailing zeros are counted with a count of
leading or trailing zero bits instead of divisions.

**The destructor's walk (theme <a class="nj-theme" href="#theme-7" title="theme 7">7</a>).** While the destructor's walk
empties a container, the slot of that container's last child holds the link back to the container's parent:

```cpp
// descend into the last child of cur, reversing the link
basic_json& slot = last_child(cur);
take(tmp, slot);    // the child's contents
take(slot, prev);   // its slot now remembers cur's parent
take(prev, cur);    // cur becomes the parent
take(cur, tmp);     // the child becomes cur
// on the way up: read the parent back out of prev's last slot, pop that slot, free cur
```

<p class="nj-code-caption" markdown>One step down in the destructor's walk: the emptied slot remembers the way back.</p>

`take()` moves the 16 bytes of type and value and leaves a null behind. The way back needs no memory: the slot that
holds the link is the one being emptied, it stays the last child until the walk comes back up, and only then, after the
link is taken out, is it removed. A child is removed only when it is a scalar or an empty container, so each removal
destroys one level at most.

### J. Validation

A faster path is only useful if it gives the same result as the slow one, including the same error at the same byte.
These are the checks behind the themes:

- **Error positions** (theme <a class="nj-theme" href="#theme-1" title="theme 1">1</a>). The contiguous fast paths defer
  to the byte path on anything malformed. On 481,000 documents, 298,333 of them with errors, the contiguous and the byte
  path reported the same exception, message, byte, line and column, except for the one deliberate correction listed in
  [Appendix F](#f-behavior-changes).
- **Stream windows** (theme <a class="nj-theme" href="#theme-1" title="theme 1">1</a>). A test `streambuf` hands out get
  areas of 1–4,096 bytes, so that every token crosses a window edge at every offset, and the result is compared with a
  `streambuf` without a get area, which takes the old path. The `FILE` window is checked the same way, with `FILE`
  buffers of 1 to 70 bytes, unbuffered files, and characters pushed back with `ungetc()` before the parse, on macOS and
  glibc.
- **The fused parser** (theme <a class="nj-theme" href="#theme-1" title="theme 1">1</a>). `contiguous_parser` is
  compared with the byte path on corner cases of literals, numbers, escapes, surrogates and UTF-8, on 1,500 generated
  documents, every truncation of the short ones and random mutations, and on nesting across the 64-level words of its
  stack: the same values with the same number types and float bits, the same exception messages, the same `accept()`
  verdicts and the same `sax_parse()` events, also for handlers that stop early (242,118 assertions). A fuzzer that
  compares the `sax_parse()` events of both paths ran 9 million inputs without a finding.
- **Differential fuzzing of the input kinds.** Every fuzz input is also parsed from an `std::istringstream`, from
  `std::list` iterators (the byte path) and from a `FILE*`, and the value, the exception id, the message, and the byte
  offset must be identical ([#5827][5827]).
- **Guard pages.** The input is copied so that its last byte is the last readable byte of a page, and the next page is
  unmapped. AddressSanitizer misses an over-read into the slack of the same heap allocation, and fuzzers rarely end an
  input exactly at a page boundary; this test crashes on any over-read by one byte ([#5826][5826]).
- **Number conversion** (theme <a class="nj-theme" href="#theme-3" title="theme 3">3</a>). 6.5 million float tokens were
  compared with `strtod`, among them 60,000 exact halfway cases, and 900,000 hard cases from other test suites: all
  bit-identical. `json_document`'s batched float output is byte-identical to the general writer for 10⁹ generated
  tokens.
- **Unchanged output.** For this post, we checked that 3.13.0 writes the same bytes as 3.12.0 in all five binary formats
  for 39 test files, and the same JSON text for `twitter.json` and `citm_catalog.json`. The changes of float output are
  listed in [Appendix F](#f-behavior-changes).
- **`json_document` against `json`.** A fuzzer parses every input with both and requires the same verdict, the same
  value and the same error message, from a borrowed string and from an exact-size buffer without a closing NUL
  ([`fuzzer-parse_json_view.cpp`](https://github.com/nlohmann/json/blob/develop/tests/src/fuzzer-parse_json_view.cpp)).
- **Comparison** (theme <a class="nj-theme" href="#theme-7" title="theme 7">7</a>). The single-pass `operator<` was
  compared with the old code on 68,121 pairs of values.
- **Mutation checks.** Break a fast path on purpose (skip one byte too many, mark `"` as copyable) and make sure the
  tests notice. Marking the quote as copyable in the short-string table fails 4,551 assertions.
- **The comparison with other libraries.** Before anything is timed, every way's result is checked: the same values, the
  same string bytes, the same sum of all numbers (to the last bit where they are added in the same order), and an output
  that reads back as the expected document. The expected values come from nlohmann/json; the Rust programs compute their
  own with serde_json, and the two agree ([Appendix E](#e-comparison-with-other-libraries)).

[5185]: https://github.com/nlohmann/json/pull/5185
[5233]: https://github.com/nlohmann/json/pull/5233
[5234]: https://github.com/nlohmann/json/pull/5234
[5268]: https://github.com/nlohmann/json/pull/5268
[5283]: https://github.com/nlohmann/json/pull/5283
[5285]: https://github.com/nlohmann/json/pull/5285
[5286]: https://github.com/nlohmann/json/pull/5286
[5328]: https://github.com/nlohmann/json/pull/5328
[5389]: https://github.com/nlohmann/json/pull/5389
[5390]: https://github.com/nlohmann/json/pull/5390
[5449]: https://github.com/nlohmann/json/pull/5449
[5457]: https://github.com/nlohmann/json/pull/5457
[5458]: https://github.com/nlohmann/json/pull/5458
[5461]: https://github.com/nlohmann/json/pull/5461
[5490]: https://github.com/nlohmann/json/pull/5490
[5501]: https://github.com/nlohmann/json/pull/5501
[5531]: https://github.com/nlohmann/json/pull/5531
[5547]: https://github.com/nlohmann/json/pull/5547
[5553]: https://github.com/nlohmann/json/pull/5553
[5555]: https://github.com/nlohmann/json/pull/5555
[5592]: https://github.com/nlohmann/json/pull/5592
[5609]: https://github.com/nlohmann/json/pull/5609
[5617]: https://github.com/nlohmann/json/pull/5617
[5620]: https://github.com/nlohmann/json/pull/5620
[5622]: https://github.com/nlohmann/json/pull/5622
[5627]: https://github.com/nlohmann/json/pull/5627
[5628]: https://github.com/nlohmann/json/pull/5628
[5630]: https://github.com/nlohmann/json/pull/5630
[5633]: https://github.com/nlohmann/json/pull/5633
[5634]: https://github.com/nlohmann/json/pull/5634
[5660]: https://github.com/nlohmann/json/issues/5660
[5738]: https://github.com/nlohmann/json/pull/5738
[5741]: https://github.com/nlohmann/json/pull/5741
[5746]: https://github.com/nlohmann/json/pull/5746
[5762]: https://github.com/nlohmann/json/pull/5762
[5782]: https://github.com/nlohmann/json/pull/5782
[5793]: https://github.com/nlohmann/json/pull/5793
[5809]: https://github.com/nlohmann/json/pull/5809
[5810]: https://github.com/nlohmann/json/pull/5810
[5822]: https://github.com/nlohmann/json/pull/5822
[5824]: https://github.com/nlohmann/json/pull/5824
[5826]: https://github.com/nlohmann/json/pull/5826
[5827]: https://github.com/nlohmann/json/pull/5827
[5828]: https://github.com/nlohmann/json/pull/5828
[5832]: https://github.com/nlohmann/json/pull/5832
[5833]: https://github.com/nlohmann/json/pull/5833
[5834]: https://github.com/nlohmann/json/pull/5834
[5835]: https://github.com/nlohmann/json/pull/5835
[5836]: https://github.com/nlohmann/json/pull/5836
[5838]: https://github.com/nlohmann/json/pull/5838
[5839]: https://github.com/nlohmann/json/pull/5839
[5840]: https://github.com/nlohmann/json/pull/5840
[5851]: https://github.com/nlohmann/json/pull/5851
[5852]: https://github.com/nlohmann/json/pull/5852
[5853]: https://github.com/nlohmann/json/pull/5853
[5854]: https://github.com/nlohmann/json/pull/5854
[5855]: https://github.com/nlohmann/json/pull/5855
[5861]: https://github.com/nlohmann/json/pull/5861
[5878]: https://github.com/nlohmann/json/pull/5878
[5879]: https://github.com/nlohmann/json/pull/5879
[5882]: https://github.com/nlohmann/json/pull/5882
[5883]: https://github.com/nlohmann/json/pull/5883
[5884]: https://github.com/nlohmann/json/pull/5884
[5885]: https://github.com/nlohmann/json/pull/5885
[5886]: https://github.com/nlohmann/json/pull/5886
[5888]: https://github.com/nlohmann/json/pull/5888
[5889]: https://github.com/nlohmann/json/pull/5889
[5890]: https://github.com/nlohmann/json/pull/5890
[5902]: https://github.com/nlohmann/json/pull/5902
[5908]: https://github.com/nlohmann/json/pull/5908
[5915]: https://github.com/nlohmann/json/pull/5915
[5919]: https://github.com/nlohmann/json/pull/5919
[5921]: https://github.com/nlohmann/json/pull/5921
[5926]: https://github.com/nlohmann/json/pull/5926
[5964]: https://github.com/nlohmann/json/pull/5964
[5968]: https://github.com/nlohmann/json/pull/5968
[5970]: https://github.com/nlohmann/json/pull/5970
[5971]: https://github.com/nlohmann/json/pull/5971
[5975]: https://github.com/nlohmann/json/pull/5975
[5978]: https://github.com/nlohmann/json/pull/5978
[5979]: https://github.com/nlohmann/json/pull/5979
[5980]: https://github.com/nlohmann/json/pull/5980
[5981]: https://github.com/nlohmann/json/pull/5981
[5982]: https://github.com/nlohmann/json/pull/5982
[6008]: https://github.com/nlohmann/json/pull/6008
[6020]: https://github.com/nlohmann/json/pull/6020
[6028]: https://github.com/nlohmann/json/pull/6028
[6029]: https://github.com/nlohmann/json/pull/6029
[6030]: https://github.com/nlohmann/json/pull/6030
[6031]: https://github.com/nlohmann/json/pull/6031
[6033]: https://github.com/nlohmann/json/pull/6033
[6039]: https://github.com/nlohmann/json/pull/6039
