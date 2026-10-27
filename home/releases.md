# Releases

This section summarizes the notable changes of every release and links to the relevant documentation.
The **complete release notes** — including all changes, the download files, and their checksums — are
published on the [GitHub releases page](https://github.com/nlohmann/json/releases).

!!! info "Unreleased changes"

    This documentation is built from the `develop` branch and may describe changes that are not part of a release
    yet. Their version numbers are followed by an <span class="unreleased-version">unreleased</span> badge.

Every release has its own page with a summary of its notable changes and an overview of the API that was added or
changed in it. The API overview is generated from the "Version history" section of the
[API pages](../../api/basic_json/index.md); it is not a change log, but helps to see whether a feature is available in
the version you use.

All releases at a glance (hover a marker for its version and date):

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-fig--timeline" viewBox="0 0 880 164" role="img" aria-labelledby="nj-int-tl-title" xmlns="http://www.w3.org/2000/svg">
<title id="nj-int-tl-title">Timeline from the first commit (2013-07-04) and the 44 releases from v1.0.0 (2015-12-28) to v3.12.0 (2025-04-11): 17 minor or major releases, drawn as filled dots with their version above the axis, and 27 patch releases, drawn as rings. The first commit is drawn as a diamond.</title>
<line class="nj-int-grid" x1="24.0" y1="78" x2="24.0" y2="102"/>
<text class="nj-int-year" x="55.7" y="118">2013</text>
<line class="nj-int-grid" x1="88.0" y1="78" x2="88.0" y2="102"/>
<text class="nj-int-year" x="119.7" y="118">2014</text>
<line class="nj-int-grid" x1="151.9" y1="78" x2="151.9" y2="102"/>
<text class="nj-int-year" x="183.6" y="118">2015</text>
<line class="nj-int-grid" x1="215.9" y1="78" x2="215.9" y2="102"/>
<text class="nj-int-year" x="247.8" y="118">2016</text>
<line class="nj-int-grid" x1="280.0" y1="78" x2="280.0" y2="102"/>
<text class="nj-int-year" x="311.7" y="118">2017</text>
<line class="nj-int-grid" x1="344.0" y1="78" x2="344.0" y2="102"/>
<text class="nj-int-year" x="375.7" y="118">2018</text>
<line class="nj-int-grid" x1="407.9" y1="78" x2="407.9" y2="102"/>
<text class="nj-int-year" x="439.6" y="118">2019</text>
<line class="nj-int-grid" x1="471.9" y1="78" x2="471.9" y2="102"/>
<text class="nj-int-year" x="503.8" y="118">2020</text>
<line class="nj-int-grid" x1="536.0" y1="78" x2="536.0" y2="102"/>
<text class="nj-int-year" x="567.7" y="118">2021</text>
<line class="nj-int-grid" x1="600.0" y1="78" x2="600.0" y2="102"/>
<text class="nj-int-year" x="631.7" y="118">2022</text>
<line class="nj-int-grid" x1="663.9" y1="78" x2="663.9" y2="102"/>
<text class="nj-int-year" x="695.7" y="118">2023</text>
<line class="nj-int-grid" x1="727.9" y1="78" x2="727.9" y2="102"/>
<text class="nj-int-year" x="759.8" y="118">2024</text>
<line class="nj-int-grid" x1="792.0" y1="78" x2="792.0" y2="102"/>
<text class="nj-int-year" x="823.8" y="118">2025</text>
<line class="nj-int-grid" x1="856.0" y1="78" x2="856.0" y2="102"/>
<line class="nj-int-axis" x1="24" y1="94" x2="856" y2="94"/>
<path class="nj-int-axis" fill="none" d="M215.2 131 V136 H219.9 V131"/>
<text class="nj-int-major" x="215.2" y="153" text-anchor="start">1.x</text>
<path class="nj-int-axis" fill="none" d="M246.5 131 V136 H289.7 V131"/>
<text class="nj-int-major" x="268.1" y="153" text-anchor="middle">2.x</text>
<path class="nj-int-axis" fill="none" d="M341.3 131 V136 H809.6 V131"/>
<text class="nj-int-major" x="575.5" y="153" text-anchor="middle">3.x</text>
<line class="nj-int-leader" x1="56.2" y1="85" x2="56.2" y2="87"/>
<text class="nj-int-label" x="56.2" y="82">first commit</text>
<line class="nj-int-leader" x1="215.2" y1="85" x2="215.2" y2="87"/>
<text class="nj-int-label" x="215.2" y="82">1.0</text>
<line class="nj-int-leader" x1="219.9" y1="68" x2="219.9" y2="87"/>
<text class="nj-int-label" x="219.9" y="65">1.1</text>
<line class="nj-int-leader" x1="246.5" y1="85" x2="246.5" y2="87"/>
<text class="nj-int-label" x="246.5" y="82">2.0</text>
<line class="nj-int-leader" x1="284.7" y1="85" x2="284.7" y2="87"/>
<text class="nj-int-label" x="284.7" y="82">2.1</text>
<line class="nj-int-leader" x1="341.3" y1="85" x2="341.3" y2="87"/>
<text class="nj-int-label" x="341.3" y="82">3.0</text>
<line class="nj-int-leader" x1="349.4" y1="68" x2="349.4" y2="87"/>
<text class="nj-int-label" x="349.4" y="65">3.1</text>
<line class="nj-int-leader" x1="384.5" y1="85" x2="384.5" y2="87"/>
<text class="nj-int-label" x="384.5" y="82">3.2</text>
<line class="nj-int-leader" x1="392.5" y1="68" x2="392.5" y2="87"/>
<text class="nj-int-label" x="392.5" y="65">3.3</text>
<line class="nj-int-leader" x1="396.9" y1="51" x2="396.9" y2="87"/>
<text class="nj-int-label" x="396.9" y="48">3.4</text>
<line class="nj-int-leader" x1="406.2" y1="34" x2="406.2" y2="87"/>
<text class="nj-int-label" x="406.2" y="31">3.5</text>
<line class="nj-int-leader" x1="421.6" y1="85" x2="421.6" y2="87"/>
<text class="nj-int-label" x="421.6" y="82">3.6</text>
<line class="nj-int-leader" x1="444.4" y1="68" x2="444.4" y2="87"/>
<text class="nj-int-label" x="444.4" y="65">3.7</text>
<line class="nj-int-leader" x1="500.8" y1="85" x2="500.8" y2="87"/>
<text class="nj-int-label" x="500.8" y="82">3.8</text>
<line class="nj-int-leader" x1="508.3" y1="68" x2="508.3" y2="87"/>
<text class="nj-int-label" x="508.3" y="65">3.9</text>
<line class="nj-int-leader" x1="576.0" y1="85" x2="576.0" y2="87"/>
<text class="nj-int-label" x="576.0" y="82">3.10</text>
<line class="nj-int-leader" x1="637.1" y1="85" x2="637.1" y2="87"/>
<text class="nj-int-label" x="637.1" y="82">3.11</text>
<line class="nj-int-leader" x1="809.6" y1="85" x2="809.6" y2="87"/>
<text class="nj-int-label" x="809.6" y="82">3.12</text>
<g><title>First commit 2013-07-04</title><circle class="nj-int-hit" cx="56.2" cy="94" r="9"/><path class="nj-int-minor" d="M56.2 94 l7 -7 l7 7 l-7 7z" transform="translate(-7 0)"/></g>
<g><title>v2.0.1 released 2016-06-28</title><circle class="nj-int-hit" cx="247.2" cy="94" r="9"/><circle class="nj-int-patch" cx="247.2" cy="94" r="3.5"/></g>
<g><title>v2.0.2 released 2016-07-31</title><circle class="nj-int-hit" cx="253.0" cy="94" r="9"/><circle class="nj-int-patch" cx="253.0" cy="94" r="3.5"/></g>
<g><title>v2.0.3 released 2016-08-31</title><circle class="nj-int-hit" cx="258.5" cy="94" r="9"/><circle class="nj-int-patch" cx="258.5" cy="94" r="3.5"/></g>
<g><title>v2.0.4 released 2016-09-11</title><circle class="nj-int-hit" cx="260.4" cy="94" r="9"/><circle class="nj-int-patch" cx="260.4" cy="94" r="3.5"/></g>
<g><title>v2.0.5 released 2016-09-14</title><circle class="nj-int-hit" cx="260.9" cy="94" r="9"/><circle class="nj-int-patch" cx="260.9" cy="94" r="3.5"/></g>
<g><title>v2.0.6 released 2016-10-15</title><circle class="nj-int-hit" cx="266.3" cy="94" r="9"/><circle class="nj-int-patch" cx="266.3" cy="94" r="3.5"/></g>
<g><title>v2.0.7 released 2016-11-02</title><circle class="nj-int-hit" cx="269.5" cy="94" r="9"/><circle class="nj-int-patch" cx="269.5" cy="94" r="3.5"/></g>
<g><title>v2.0.8 released 2016-12-02</title><circle class="nj-int-hit" cx="274.8" cy="94" r="9"/><circle class="nj-int-patch" cx="274.8" cy="94" r="3.5"/></g>
<g><title>v2.0.9 released 2016-12-16</title><circle class="nj-int-hit" cx="277.2" cy="94" r="9"/><circle class="nj-int-patch" cx="277.2" cy="94" r="3.5"/></g>
<g><title>v2.0.10 released 2017-01-02</title><circle class="nj-int-hit" cx="280.2" cy="94" r="9"/><circle class="nj-int-patch" cx="280.2" cy="94" r="3.5"/></g>
<g><title>v2.1.1 released 2017-02-25</title><circle class="nj-int-hit" cx="289.7" cy="94" r="9"/><circle class="nj-int-patch" cx="289.7" cy="94" r="3.5"/></g>
<g><title>v3.0.1 released 2017-12-29</title><circle class="nj-int-hit" cx="343.4" cy="94" r="9"/><circle class="nj-int-patch" cx="343.4" cy="94" r="3.5"/></g>
<g><title>v3.1.1 released 2018-02-13</title><circle class="nj-int-hit" cx="351.5" cy="94" r="9"/><circle class="nj-int-patch" cx="351.5" cy="94" r="3.5"/></g>
<g><title>v3.1.2 released 2018-03-14</title><circle class="nj-int-hit" cx="356.6" cy="94" r="9"/><circle class="nj-int-patch" cx="356.6" cy="94" r="3.5"/></g>
<g><title>v3.7.1 released 2019-11-06</title><circle class="nj-int-hit" cx="462.1" cy="94" r="9"/><circle class="nj-int-patch" cx="462.1" cy="94" r="3.5"/></g>
<g><title>v3.7.2 released 2019-11-10</title><circle class="nj-int-hit" cx="462.8" cy="94" r="9"/><circle class="nj-int-patch" cx="462.8" cy="94" r="3.5"/></g>
<g><title>v3.7.3 released 2019-11-17</title><circle class="nj-int-hit" cx="464.0" cy="94" r="9"/><circle class="nj-int-patch" cx="464.0" cy="94" r="3.5"/></g>
<g><title>v3.9.1 released 2020-08-06</title><circle class="nj-int-hit" cx="510.1" cy="94" r="9"/><circle class="nj-int-patch" cx="510.1" cy="94" r="3.5"/></g>
<g><title>v3.10.1 released 2021-08-24</title><circle class="nj-int-hit" cx="577.2" cy="94" r="9"/><circle class="nj-int-patch" cx="577.2" cy="94" r="3.5"/></g>
<g><title>v3.10.2 released 2021-08-26</title><circle class="nj-int-hit" cx="577.6" cy="94" r="9"/><circle class="nj-int-patch" cx="577.6" cy="94" r="3.5"/></g>
<g><title>v3.10.3 released 2021-10-08</title><circle class="nj-int-hit" cx="585.1" cy="94" r="9"/><circle class="nj-int-patch" cx="585.1" cy="94" r="3.5"/></g>
<g><title>v3.10.4 released 2021-10-16</title><circle class="nj-int-hit" cx="586.5" cy="94" r="9"/><circle class="nj-int-patch" cx="586.5" cy="94" r="3.5"/></g>
<g><title>v3.10.5 released 2022-01-03</title><circle class="nj-int-hit" cx="600.3" cy="94" r="9"/><circle class="nj-int-patch" cx="600.3" cy="94" r="3.5"/></g>
<g><title>v3.11.2 released 2022-08-12</title><circle class="nj-int-hit" cx="639.1" cy="94" r="9"/><circle class="nj-int-patch" cx="639.1" cy="94" r="3.5"/></g>
<g><title>v3.11.3 released 2023-11-28</title><circle class="nj-int-hit" cx="721.9" cy="94" r="9"/><circle class="nj-int-patch" cx="721.9" cy="94" r="3.5"/></g>
<g><title>v1.0.0 released 2015-12-28</title><circle class="nj-int-hit" cx="215.2" cy="94" r="9"/><circle class="nj-int-minor" cx="215.2" cy="94" r="6"/></g>
<g><title>v1.1.0 released 2016-01-24</title><circle class="nj-int-hit" cx="219.9" cy="94" r="9"/><circle class="nj-int-minor" cx="219.9" cy="94" r="6"/></g>
<g><title>v2.0.0 released 2016-06-24</title><circle class="nj-int-hit" cx="246.5" cy="94" r="9"/><circle class="nj-int-minor" cx="246.5" cy="94" r="6"/></g>
<g><title>v2.1.0 released 2017-01-28</title><circle class="nj-int-hit" cx="284.7" cy="94" r="9"/><circle class="nj-int-minor" cx="284.7" cy="94" r="6"/></g>
<g><title>v3.0.0 released 2017-12-17</title><circle class="nj-int-hit" cx="341.3" cy="94" r="9"/><circle class="nj-int-minor" cx="341.3" cy="94" r="6"/></g>
<g><title>v3.1.0 released 2018-02-01</title><circle class="nj-int-hit" cx="349.4" cy="94" r="9"/><circle class="nj-int-minor" cx="349.4" cy="94" r="6"/></g>
<g><title>v3.2.0 released 2018-08-20</title><circle class="nj-int-hit" cx="384.5" cy="94" r="9"/><circle class="nj-int-minor" cx="384.5" cy="94" r="6"/></g>
<g><title>v3.3.0 released 2018-10-05</title><circle class="nj-int-hit" cx="392.5" cy="94" r="9"/><circle class="nj-int-minor" cx="392.5" cy="94" r="6"/></g>
<g><title>v3.4.0 released 2018-10-30</title><circle class="nj-int-hit" cx="396.9" cy="94" r="9"/><circle class="nj-int-minor" cx="396.9" cy="94" r="6"/></g>
<g><title>v3.5.0 released 2018-12-22</title><circle class="nj-int-hit" cx="406.2" cy="94" r="9"/><circle class="nj-int-minor" cx="406.2" cy="94" r="6"/></g>
<g><title>v3.6.0, v3.6.1 released 2019-03-20</title><circle class="nj-int-hit" cx="421.6" cy="94" r="9"/><circle class="nj-int-minor" cx="421.6" cy="94" r="6"/></g>
<g><title>v3.7.0 released 2019-07-28</title><circle class="nj-int-hit" cx="444.4" cy="94" r="9"/><circle class="nj-int-minor" cx="444.4" cy="94" r="6"/></g>
<g><title>v3.8.0 released 2020-06-14</title><circle class="nj-int-hit" cx="500.8" cy="94" r="9"/><circle class="nj-int-minor" cx="500.8" cy="94" r="6"/></g>
<g><title>v3.9.0 released 2020-07-27</title><circle class="nj-int-hit" cx="508.3" cy="94" r="9"/><circle class="nj-int-minor" cx="508.3" cy="94" r="6"/></g>
<g><title>v3.10.0 released 2021-08-17</title><circle class="nj-int-hit" cx="576.0" cy="94" r="9"/><circle class="nj-int-minor" cx="576.0" cy="94" r="6"/></g>
<g><title>v3.11.0, v3.11.1 released 2022-08-01</title><circle class="nj-int-hit" cx="637.1" cy="94" r="9"/><circle class="nj-int-minor" cx="637.1" cy="94" r="6"/></g>
<g><title>v3.12.0 released 2025-04-11</title><circle class="nj-int-hit" cx="809.6" cy="94" r="9"/><circle class="nj-int-minor" cx="809.6" cy="94" r="6"/></g>
</svg>

</div>

<p class="nj-caption" markdown>From the first commit (diamond) in 2013 to the latest release, on a time axis by year. Filled dots with a version label are minor or major releases, rings are patch releases.</p>

## Unreleased

| Release | Date | Summary |
|---------|------|---------|
| [Unreleased](unreleased.md) |  | Changes on the `develop` branch that are not part of a release yet. |

## Version 3.12.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.12.0](v3.12.0.md) | 2025-04-11 | Fixes bugs found in 3.11.3 and adds several features. No public API was removed or renamed. **Highlights:** diagnostic byte positions (`start_pos`/`end_pos`); templated conversion macros and `NLOHMANN_DEFINE_DERIVED_TYPE`; `std::optional` support. |

## Version 3.11.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.11.3](v3.11.3.md) | 2023-11-28 | Adds features and fixes bugs found in 3.11.2. All changes are backward-compatible. **Highlights:** custom base class for `basic_json`; serialization-only conversion macros; Bazel and Swift Package Manager support. |
| [v3.11.2](v3.11.2.md) | 2022-08-12 | Fixes bugs found in 3.11.1 and restructures the namespace. All changes are backward-compatible. **Highlights:** fixes `value` for strings and size types; restores `json_pointer` as associative-container key; restructured inline namespace. |
| [v3.11.1](v3.11.1.md) | 2022-08-01 | Fixes a regression from 3.11.0. All changes are backward-compatible. **Highlights:** restores the global `_json` and `_json_pointer` literals. |
| [v3.11.0](v3.11.0.md) | 2022-08-01 | One of the largest releases ever. All changes are backward-compatible. **Highlights:** `std::string_view` keys; BJData binary format; C++20 support including `operator<=>`. |

## Version 3.10.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.10.5](v3.10.5.md) | 2022-01-03 | Bug-fix release. All changes are backward-compatible. **Highlights:** guards the `std::filesystem` conversions with `JSON_HAS_FILESYSTEM`. |
| [v3.10.4](v3.10.4.md) | 2021-10-16 | Fixes regressions introduced in 3.10.0. All changes are backward-compatible. **Highlights:** fixes the `std::filesystem::path` conversion; fixes types with explicit defaulted constructors; fixes `std::find`/`std::remove` return values. |
| [v3.10.3](v3.10.3.md) | 2021-10-08 | Fixes more regressions from 3.10.0. All changes are backward-compatible. **Highlights:** fixes extended-diagnostics assertions in `update` and array insertion; custom allocators for binary output; conversion from `begin()`/`end()`-only types. |
| [v3.10.2](v3.10.2.md) | 2021-08-26 | Re-release of 3.10.1, whose Git tag pointed at the wrong commit due to a bug in the release script. All changes are backward-compatible. **Highlights:** re-release of 3.10.1 with the correct Git tag. |
| [v3.10.1](v3.10.1.md) | 2021-08-24 | Fixes a regression from 3.10.0. All changes are backward-compatible. **Highlights:** fixes an extended-diagnostics assertion with `ordered_json`; hardens the GDB pretty-printer. |
| [v3.10.0](v3.10.0.md) | 2021-08-17 | Feature release. All changes are backward-compatible. **Highlights:** extended diagnostic messages (`JSON_DIAGNOSTICS`); GDB pretty-printer; CBOR tag storage. |

## Version 3.9.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.9.1](v3.9.1.md) | 2020-08-06 | Fixes two regressions from 3.9.0. All changes are backward-compatible. **Highlights:** accepts consecutive comments; completes the `ordered_json` interface. |
| [v3.9.0](v3.9.0.md) | 2020-07-27 | Feature release adding four long-requested features. All changes are backward-compatible. **Highlights:** comment parsing; `ordered_json`; switch to disable implicit conversions. |

## Version 3.8.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.8.0](v3.8.0.md) | 2020-06-14 | Feature release. All changes are backward-compatible. **Highlights:** binary value type for CBOR, BSON, and MessagePack; input adapters for any `LegacyInputIterator` container; fixes `contains` for JSON pointers. |

## Version 3.7.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.7.3](v3.7.3.md) | 2019-11-17 | Fixes a regression from 3.7.2 that could yield quadratic complexity in destructor calls. All changes are backward-compatible. **Highlights:** fixes quadratic complexity in destructor calls. |
| [v3.7.2](v3.7.2.md) | 2019-11-10 | Fixes a stack overflow for deeply nested input by making the destructor iterative; parsing of JSON text is now bounded only by available memory (the binary-format parsers still recurse). All changes are backward-compatible. **Highlights:** iterative destructor fixes a stack overflow on deeply nested input. |
| [v3.7.1](v3.7.1.md) | 2019-11-06 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes a crash when serializing the minimum `std::int64_t`; fixes `contains` for JSON pointers; `items` with custom string types. |
| [v3.7.0](v3.7.0.md) | 2019-07-28 | Convenience features and house-keeping. All changes are backward-compatible. **Highlights:** `contains` overload for JSON pointers; generic `to_string`; return value for `emplace_back`. |

## Version 3.6.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.6.1](v3.6.1.md) | 2019-03-20 | Fixes a regression (GCC 7/8 compilation) and a `<Windows.h>` build error introduced in 3.6.0. All changes are backward-compatible. **Highlights:** fixes a GCC 7/8 compilation regression; fixes a `<Windows.h>` build error. |
| [v3.6.0](v3.6.0.md) | 2019-03-20 | Feature release. All changes are backward-compatible. **Highlights:** reworked JSON pointer interface; `contains` function; faster integer serialization. |

## Version 3.5.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.5.0](v3.5.0.md) | 2018-12-22 | Feature release. All changes are backward-compatible. **Highlights:** structured bindings via `items`; reading from `FILE*`; fixes `eofbit` handling on streams. |

## Version 3.4.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.4.0](v3.4.0.md) | 2018-10-30 | Feature release. All changes are backward-compatible. **Highlights:** BSON support; Unicode error handlers for `dump`; `NLOHMANN_JSON_SERIALIZE_ENUM`. |

## Version 3.3.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.3.0](v3.3.0.md) | 2018-10-05 | Feature release. All changes are backward-compatible. **Highlights:** GCC 4.8 support; `get_to`; overhauled CMake integration. |

## Version 3.2.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.2.0](v3.2.0.md) | 2018-08-20 | Feature release. All changes are backward-compatible. **Highlights:** SAX interface and non-recursive parser; parsing from wide strings; conversion to `std::string_view`. |

## Version 3.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.1.2](v3.1.2.md) | 2018-03-14 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes a memory leak in the parser callback; user-defined string types in parser and serializer. |
| [v3.1.1](v3.1.1.md) | 2018-02-13 | Bug-fix release. All changes are backward-compatible. **Highlights:** fixes parsing of indefinite-length CBOR strings; fixes a user-defined conversion to vector types; fixes UBJSON overflow detection. |
| [v3.1.0](v3.1.0.md) | 2018-02-01 | Feature release. All changes are backward-compatible. **Highlights:** UBJSON support; JSON Merge Patch; Grisu2 floating-point output. |

## Version 3.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v3.0.1](v3.0.1.md) | 2017-12-29 | Fixes small issues in the [JSON Pointer](../../features/json_pointer.md) and [JSON Patch](../../features/json_patch.md) implementations (invalid "copy" targets and non-integer array indices). All changes are backward-compatible. **Highlights:** fixes invalid JSON Patch "copy" targets; fixes non-integer array indices in JSON Pointer. |
| [v3.0.0](v3.0.0.md) | 2017-12-17 | First 3.x release — a major release with breaking changes (see the [migration guide](../../integration/migration_guide.md)). **Highlights:** user-defined exceptions with identifiers; non-throwing `accept` and `allow_exceptions`; `update` to merge objects. |

## Version 2.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v2.1.1](v2.1.1.md) | 2017-02-25 | Bug-fix release. All changes are backward-compatible. **Highlights:** locale-independent number parsing and serialization; correct floating-point round-tripping; GPG-signed commits and files. |
| [v2.1.0](v2.1.0.md) | 2017-01-28 | Feature release. All changes are backward-compatible. **Highlights:** conversions from and to arbitrary user-defined types; `meta` function; `JSON_NOEXCEPTION`. |

## Version 2.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v2.0.10](v2.0.10.md) | 2017-01-02 | Fixes several security-relevant bugs in the CBOR and MessagePack parsers found by OSS-Fuzz. All changes are backward-compatible. **Highlights:** fixes security-relevant bugs in the CBOR parser; fixes security-relevant bugs in the MessagePack parser. |
| [v2.0.9](v2.0.9.md) | 2016-12-16 | Adds the [CBOR](../../features/binary_formats/cbor.md) and [MessagePack](../../features/binary_formats/messagepack.md) binary formats. All changes are backward-compatible. **Highlights:** CBOR support; MessagePack support. |
| [v2.0.8](v2.0.8.md) | 2016-12-02 | Adds the [`emplace`](../../api/basic_json/emplace.md) and [`emplace_back`](../../api/basic_json/emplace_back.md) functions and improves parsing and serialization performance. All changes are backward-compatible. **Highlights:** `emplace` and `emplace_back`; faster parsing; faster serialization. |
| [v2.0.7](v2.0.7.md) | 2016-11-02 | Fixes several parser bugs found through the "Parsing JSON is a Minefield" study (short files, encoding detection, surrogate pairs). All changes are backward-compatible. **Highlights:** fixes short-file handling; fixes encoding detection; fixes surrogate pairs. |
| [v2.0.6](v2.0.6.md) | 2016-10-15 | Fixes [`operator[]`](../../api/basic_json/operator%5B%5D.md) for [JSON pointers](../../features/json_pointer.md) so that it creates missing values like the other overloads. All changes are backward-compatible. **Highlights:** `operator[]` creates missing values for JSON pointers. |
| [v2.0.5](v2.0.5.md) | 2016-09-14 | Fixes a remaining stream end-of-file detection bug in the parser. All changes are backward-compatible. **Highlights:** fixes a remaining stream end-of-file bug. |
| [v2.0.4](v2.0.4.md) | 2016-09-11 | Fixes stream end-of-file detection in the parser. All changes are backward-compatible. **Highlights:** fixes stream end-of-file detection. |
| [v2.0.3](v2.0.3.md) | 2016-08-31 | Generalizes the parser to accept any contiguous sequence of one-byte elements and deprecates the input-stream constructor in favor of the [`parse`](../../api/basic_json/parse.md) function. All changes are backward-compatible. **Highlights:** parser accepts any contiguous sequence of one-byte elements; deprecates the input-stream constructor in favor of `parse`. |
| [v2.0.2](v2.0.2.md) | 2016-07-31 | Overhauls the parser (now rejecting unescaped control characters), tightens the class invariants, and cleans up the code. All changes are backward-compatible. **Highlights:** overhauled parser rejecting unescaped control characters; tighter class invariants; code cleanup. |
| [v2.0.1](v2.0.1.md) | 2016-06-28 | Fixes a performance regression in the [`dump`](../../api/basic_json/dump.md) function by adjusting the stream locale once per serialization. All changes are backward-compatible. **Highlights:** fixes a performance regression in `dump`. |
| [v2.0.0](v2.0.0.md) | 2016-06-24 | Feature release with a minor (potentially non-backward-compatible) API change from added `noexcept` and `constexpr` specifiers. **Highlights:** JSON Pointer support in `at` and `operator[]`, plus `flatten` and `unflatten`; JSON Patch via `diff` and `patch`; unsigned 64-bit integers. |

## Version 1.1.x

| Release | Date | Summary |
|---------|------|---------|
| [v1.1.0](v1.1.0.md) | 2016-01-24 | Bug-fix and feature release. All changes are backward-compatible. **Highlights:** improved floating-point round-tripping; `get_ref`; runtime assertions. |

## Version 1.0.x

| Release | Date | Summary |
|---------|------|---------|
| [v1.0.0](v1.0.0.md) | 2015-12-28 | First official release. |

## See also

- [Migration Guide](../../integration/migration_guide.md) — how to future-proof your code for the next
  major version and replace deprecated functions.
- [Roadmap: Version 4.0](../../community/roadmap.md#version-40) — what the next major version will change and how to
  try it today.
