# Quality assurance

Ensuring quality is paramount for this project, particularly because [numerous other projects](../home/customers.md)
depend on it. Each commit to the library undergoes rigorous checks against the following requirements, and any
violations will result in a failed build.

The overview shows the checks a change passes on its way from a push or pull request to a release; the sections below
describe each of them.

<div class="nj-fig-wrap" markdown>
<svg class="nj-fig nj-exceptions-qa nj-exceptions-qa--wide" viewBox="0 0 760 808" role="img" aria-labelledby="nj-qa-title-w nj-qa-desc-w" xmlns="http://www.w3.org/2000/svg">
<title id="nj-qa-title-w">Quality assurance pipeline</title>
<desc id="nj-qa-desc-w">Every push or pull request starts these checks in parallel: Build matrix (every push / PR): 50+ compilers: G&#8203;CC, Clang, M&#8203;SVC, AppleClang, Intel, NVIDIA, ... C++11, 14, 17, 20, 23, and 26 libc++ and libstdc++ warnings: Clang -Weverything, G&#8203;CC 300+ warnings; Unit tests (doctest) (every push / PR): every public A&#8203;PI function every exception id and message all Unicode code points single header and split headers custom number, string, array, and object types; Coverage (every push / PR): unit tests cover all lines of the code base; Static analysis (every push / PR, scheduled): Clang-Tidy, Cppcheck, Infer Clang Static Analyzer (52 checkers), I&#8203;WYU, Codacy CodeQL, Semgrep, Flawfinder (also scheduled); Dynamic analysis (every push / PR): runtime assertions Valgrind (Memcheck) address and undefined behavior sanitizers, integer overflow, nullability violations; Fuzzing (every PR, continuous): CIFuzz on every pull request OSS-Fuzz: billions of inputs every crash fixed with a reproducing unit test; Style (every push / PR): Artistic Style (astyle), enforced in the C&#8203;I cpplint with 61 rules; Docs and examples (every push / PR, scheduled): every documentation example is tested; changed output fails site built with warnings as errors; links checked regularly (scheduled); Integration, supply chain (every push / PR, scheduled): CMake 3.5, 3.31.6, and 4.0.0 Meson, Swift Package Manager dependency review on every PR Dependabot daily, OpenSSF Scorecard, R&#8203;EUSE. When they pass, the change is merged into develop; a release is made only when no vulnerability alert is open.</desc>
<defs><marker id="nj-qa-arrow-w" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>
<rect class="nj-exceptions-groupbox" x="12" y="70" width="736" height="594" rx="12"/>
<rect class="nj-exceptions-stage" x="265" y="8" width="230" height="34" rx="17"/>
<text class="nj-exceptions-stagetext" x="380" y="30">push or pull request</text>
<line class="nj-exceptions-edge" x1="380" y1="42" x2="380" y2="68" marker-end="url(#nj-qa-arrow-w)"/>
<text class="nj-exceptions-group" x="26" y="94">checks, run in parallel on GitHub Actions and AppVeyor</text>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="110" width="228" height="184" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="135">Build matrix</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="146" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="160">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="188">50+ compilers: G&#8203;CC, Clang, M&#8203;SVC,</text>
<text class="nj-exceptions-line" x="40" y="206">AppleClang, Intel, NVIDIA, ...</text>
<text class="nj-exceptions-line" x="40" y="224">C++11, 14, 17, 20, 23, and 26</text>
<text class="nj-exceptions-line" x="40" y="242">libc++ and libstdc++</text>
<text class="nj-exceptions-line" x="40" y="260">warnings: Clang -Weverything,</text>
<text class="nj-exceptions-line" x="40" y="278">G&#8203;CC 300+ warnings</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="266" y="110" width="228" height="184" rx="8"/>
<text class="nj-exceptions-ctitle" x="280" y="135">Unit tests (doctest)</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="280" y="146" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="335.25" y="160">every push / PR</text>
<text class="nj-exceptions-line" x="280" y="188">every public A&#8203;PI function</text>
<text class="nj-exceptions-line" x="280" y="206">every exception id and message</text>
<text class="nj-exceptions-line" x="280" y="224">all Unicode code points</text>
<text class="nj-exceptions-line" x="280" y="242">single header and split headers</text>
<text class="nj-exceptions-line" x="280" y="260">custom number, string, array,</text>
<text class="nj-exceptions-line" x="280" y="278">and object types</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="506" y="110" width="228" height="184" rx="8"/>
<text class="nj-exceptions-ctitle" x="520" y="135">Coverage</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="520" y="146" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="575.25" y="160">every push / PR</text>
<text class="nj-exceptions-line" x="520" y="188">unit tests cover all lines</text>
<text class="nj-exceptions-line" x="520" y="206">of the code base</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="306" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="331">Static analysis</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="342" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="356">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="156.5" y="342" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="192.85" y="356">scheduled</text>
<text class="nj-exceptions-line" x="40" y="384">Clang-Tidy, Cppcheck, Infer</text>
<text class="nj-exceptions-line" x="40" y="402">Clang Static Analyzer (52</text>
<text class="nj-exceptions-line" x="40" y="420">checkers), I&#8203;WYU, Codacy</text>
<text class="nj-exceptions-line" x="40" y="438">CodeQL, Semgrep, Flawfinder</text>
<text class="nj-exceptions-line" x="40" y="456">(also scheduled)</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="266" y="306" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="280" y="331">Dynamic analysis</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="280" y="342" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="335.25" y="356">every push / PR</text>
<text class="nj-exceptions-line" x="280" y="384">runtime assertions</text>
<text class="nj-exceptions-line" x="280" y="402">Valgrind (Memcheck)</text>
<text class="nj-exceptions-line" x="280" y="420">address and undefined behavior</text>
<text class="nj-exceptions-line" x="280" y="438">sanitizers, integer overflow,</text>
<text class="nj-exceptions-line" x="280" y="456">nullability violations</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="506" y="306" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="520" y="331">Fuzzing</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="520" y="342" width="66.4" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="553.2" y="356">every PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--cont" x="592.4" y="342" width="79" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--cont" x="631.9" y="356">continuous</text>
<text class="nj-exceptions-line" x="520" y="384">CIFuzz on every pull request</text>
<text class="nj-exceptions-line" x="520" y="402">OSS-Fuzz: billions of inputs</text>
<text class="nj-exceptions-line" x="520" y="420">every crash fixed with a</text>
<text class="nj-exceptions-line" x="520" y="438">reproducing unit test</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="484" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="509">Style</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="520" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="534">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="562">Artistic Style (astyle),</text>
<text class="nj-exceptions-line" x="40" y="580">enforced in the C&#8203;I</text>
<text class="nj-exceptions-line" x="40" y="598">cpplint with 61 rules</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="266" y="484" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="280" y="509">Docs and examples</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="280" y="520" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="335.25" y="534">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="396.5" y="520" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="432.85" y="534">scheduled</text>
<text class="nj-exceptions-line" x="280" y="562">every documentation example is</text>
<text class="nj-exceptions-line" x="280" y="580">tested; changed output fails</text>
<text class="nj-exceptions-line" x="280" y="598">site built with warnings</text>
<text class="nj-exceptions-line" x="280" y="616">as errors; links checked</text>
<text class="nj-exceptions-line" x="280" y="634">regularly (scheduled)</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="506" y="484" width="228" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="520" y="509">Integration, supply chain</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="520" y="520" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="575.25" y="534">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="636.5" y="520" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="672.85" y="534">scheduled</text>
<text class="nj-exceptions-line" x="520" y="562">CMake 3.5, 3.31.6, and 4.0.0</text>
<text class="nj-exceptions-line" x="520" y="580">Meson, Swift Package Manager</text>
<text class="nj-exceptions-line" x="520" y="598">dependency review on every PR</text>
<text class="nj-exceptions-line" x="520" y="616">Dependabot daily, OpenSSF</text>
<text class="nj-exceptions-line" x="520" y="634">Scorecard, R&#8203;EUSE</text>
</g>
<line class="nj-exceptions-edge" x1="380" y1="664" x2="380" y2="690" marker-end="url(#nj-qa-arrow-w)"/>
<rect class="nj-exceptions-stage nj-exceptions-stage--merge" x="265" y="692" width="230" height="34" rx="17"/>
<text class="nj-exceptions-stagetext" x="380" y="714">merge into develop</text>
<line class="nj-exceptions-edge" x1="380" y1="726" x2="380" y2="752" marker-end="url(#nj-qa-arrow-w)"/>
<rect class="nj-exceptions-stage nj-exceptions-stage--merge" x="230" y="754" width="300" height="46" rx="23"/>
<text class="nj-exceptions-stagetext" x="380" y="776">release</text>
<text class="nj-exceptions-stagesub" x="380" y="792">no open vulnerability alert</text>
</svg>
<svg class="nj-fig nj-exceptions-qa nj-exceptions-qa--narrow" viewBox="0 0 360 1786" role="img" aria-labelledby="nj-qa-title-n nj-qa-desc-n" xmlns="http://www.w3.org/2000/svg">
<title id="nj-qa-title-n">Quality assurance pipeline</title>
<desc id="nj-qa-desc-n">Every push or pull request starts these checks in parallel: Build matrix (every push / PR): 50+ compilers: G&#8203;CC, Clang, M&#8203;SVC, AppleClang, Intel, NVIDIA, ... C++11, 14, 17, 20, 23, and 26 libc++ and libstdc++ warnings: Clang -Weverything, G&#8203;CC 300+ warnings; Unit tests (doctest) (every push / PR): every public A&#8203;PI function every exception id and message all Unicode code points single header and split headers custom number, string, array, and object types; Coverage (every push / PR): unit tests cover all lines of the code base; Static analysis (every push / PR, scheduled): Clang-Tidy, Cppcheck, Infer Clang Static Analyzer (52 checkers), I&#8203;WYU, Codacy CodeQL, Semgrep, Flawfinder (also scheduled); Dynamic analysis (every push / PR): runtime assertions Valgrind (Memcheck) address and undefined behavior sanitizers, integer overflow, nullability violations; Fuzzing (every PR, continuous): CIFuzz on every pull request OSS-Fuzz: billions of inputs every crash fixed with a reproducing unit test; Style (every push / PR): Artistic Style (astyle), enforced in the C&#8203;I cpplint with 61 rules; Docs and examples (every push / PR, scheduled): every documentation example is tested; changed output fails site built with warnings as errors; links checked regularly (scheduled); Integration, supply chain (every push / PR, scheduled): CMake 3.5, 3.31.6, and 4.0.0 Meson, Swift Package Manager dependency review on every PR Dependabot daily, OpenSSF Scorecard, R&#8203;EUSE. When they pass, the change is merged into develop; a release is made only when no vulnerability alert is open.</desc>
<defs><marker id="nj-qa-arrow-n" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="fg-head" d="M0 1 L10 5 L0 9 z"/></marker></defs>
<rect class="nj-exceptions-groupbox" x="12" y="70" width="336" height="1572" rx="12"/>
<rect class="nj-exceptions-stage" x="65" y="8" width="230" height="34" rx="17"/>
<text class="nj-exceptions-stagetext" x="180" y="30">push or pull request</text>
<line class="nj-exceptions-edge" x1="180" y1="42" x2="180" y2="68" marker-end="url(#nj-qa-arrow-n)"/>
<text class="nj-exceptions-group" x="26" y="94">checks, run in parallel</text>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="110" width="308" height="184" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="135">Build matrix</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="146" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="160">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="188">50+ compilers: G&#8203;CC, Clang, M&#8203;SVC,</text>
<text class="nj-exceptions-line" x="40" y="206">AppleClang, Intel, NVIDIA, ...</text>
<text class="nj-exceptions-line" x="40" y="224">C++11, 14, 17, 20, 23, and 26</text>
<text class="nj-exceptions-line" x="40" y="242">libc++ and libstdc++</text>
<text class="nj-exceptions-line" x="40" y="260">warnings: Clang -Weverything,</text>
<text class="nj-exceptions-line" x="40" y="278">G&#8203;CC 300+ warnings</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="306" width="308" height="184" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="331">Unit tests (doctest)</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="342" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="356">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="384">every public A&#8203;PI function</text>
<text class="nj-exceptions-line" x="40" y="402">every exception id and message</text>
<text class="nj-exceptions-line" x="40" y="420">all Unicode code points</text>
<text class="nj-exceptions-line" x="40" y="438">single header and split headers</text>
<text class="nj-exceptions-line" x="40" y="456">custom number, string, array,</text>
<text class="nj-exceptions-line" x="40" y="474">and object types</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="502" width="308" height="112" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="527">Coverage</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="538" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="552">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="580">unit tests cover all lines</text>
<text class="nj-exceptions-line" x="40" y="598">of the code base</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="626" width="308" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="651">Static analysis</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="662" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="676">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="156.5" y="662" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="192.85" y="676">scheduled</text>
<text class="nj-exceptions-line" x="40" y="704">Clang-Tidy, Cppcheck, Infer</text>
<text class="nj-exceptions-line" x="40" y="722">Clang Static Analyzer (52</text>
<text class="nj-exceptions-line" x="40" y="740">checkers), I&#8203;WYU, Codacy</text>
<text class="nj-exceptions-line" x="40" y="758">CodeQL, Semgrep, Flawfinder</text>
<text class="nj-exceptions-line" x="40" y="776">(also scheduled)</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="804" width="308" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="829">Dynamic analysis</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="840" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="854">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="882">runtime assertions</text>
<text class="nj-exceptions-line" x="40" y="900">Valgrind (Memcheck)</text>
<text class="nj-exceptions-line" x="40" y="918">address and undefined behavior</text>
<text class="nj-exceptions-line" x="40" y="936">sanitizers, integer overflow,</text>
<text class="nj-exceptions-line" x="40" y="954">nullability violations</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="982" width="308" height="148" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="1007">Fuzzing</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="1018" width="66.4" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="73.2" y="1032">every PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--cont" x="112.4" y="1018" width="79" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--cont" x="151.9" y="1032">continuous</text>
<text class="nj-exceptions-line" x="40" y="1060">CIFuzz on every pull request</text>
<text class="nj-exceptions-line" x="40" y="1078">OSS-Fuzz: billions of inputs</text>
<text class="nj-exceptions-line" x="40" y="1096">every crash fixed with a</text>
<text class="nj-exceptions-line" x="40" y="1114">reproducing unit test</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="1142" width="308" height="130" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="1167">Style</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="1178" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="1192">every push / PR</text>
<text class="nj-exceptions-line" x="40" y="1220">Artistic Style (astyle),</text>
<text class="nj-exceptions-line" x="40" y="1238">enforced in the C&#8203;I</text>
<text class="nj-exceptions-line" x="40" y="1256">cpplint with 61 rules</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="1284" width="308" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="1309">Docs and examples</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="1320" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="1334">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="156.5" y="1320" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="192.85" y="1334">scheduled</text>
<text class="nj-exceptions-line" x="40" y="1362">every documentation example is</text>
<text class="nj-exceptions-line" x="40" y="1380">tested; changed output fails</text>
<text class="nj-exceptions-line" x="40" y="1398">site built with warnings</text>
<text class="nj-exceptions-line" x="40" y="1416">as errors; links checked</text>
<text class="nj-exceptions-line" x="40" y="1434">regularly (scheduled)</text>
</g>
<g class="nj-exceptions-card">
<rect class="nj-exceptions-box" x="26" y="1462" width="308" height="166" rx="8"/>
<text class="nj-exceptions-ctitle" x="40" y="1487">Integration, supply chain</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--push" x="40" y="1498" width="110.5" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--push" x="95.25" y="1512">every push / PR</text>
<rect class="nj-exceptions-badge nj-exceptions-badge--sched" x="156.5" y="1498" width="72.7" height="20" rx="10"/>
<text class="nj-exceptions-badgetext nj-exceptions-badgetext--sched" x="192.85" y="1512">scheduled</text>
<text class="nj-exceptions-line" x="40" y="1540">CMake 3.5, 3.31.6, and 4.0.0</text>
<text class="nj-exceptions-line" x="40" y="1558">Meson, Swift Package Manager</text>
<text class="nj-exceptions-line" x="40" y="1576">dependency review on every PR</text>
<text class="nj-exceptions-line" x="40" y="1594">Dependabot daily, OpenSSF</text>
<text class="nj-exceptions-line" x="40" y="1612">Scorecard, R&#8203;EUSE</text>
</g>
<line class="nj-exceptions-edge" x1="180" y1="1642" x2="180" y2="1668" marker-end="url(#nj-qa-arrow-n)"/>
<rect class="nj-exceptions-stage nj-exceptions-stage--merge" x="65" y="1670" width="230" height="34" rx="17"/>
<text class="nj-exceptions-stagetext" x="180" y="1692">merge into develop</text>
<line class="nj-exceptions-edge" x1="180" y1="1704" x2="180" y2="1730" marker-end="url(#nj-qa-arrow-n)"/>
<rect class="nj-exceptions-stage nj-exceptions-stage--merge" x="30" y="1732" width="300" height="46" rx="23"/>
<text class="nj-exceptions-stagetext" x="180" y="1754">release</text>
<text class="nj-exceptions-stagesub" x="180" y="1770">no open vulnerability alert</text>
</svg>

</div>

<p class="nj-caption" markdown>The checks grouped by the stage at which they run, from push or pull request through the merge into develop to a release. The badge on each card says whether the check runs on every push or PR, on a schedule, or continuously.</p>

## C++ language compliance and compiler compatibility

!!! success "Requirement: Compiler support"

    Any compiler with complete C++11 support can compile the library without warnings.

Note: C++20 modules support may hit compiler-specific issues not covered by the general compiler matrix below. See [Modules](../features/modules.md#known-issues) for known issues and workarounds.

Note: Some modern features (like C++20 ranges or filesystem support) may be disabled on specific broken or incomplete toolchains even when standard feature-test macros indicate support. See [`JSON_HAS_RANGES`](../api/macros/json_has_ranges.md), [`JSON_HAS_RANGE_VIEW_CONVERSION`](../api/macros/json_has_range_view_conversion.md), and [`JSON_HAS_FILESYSTEM`](../api/macros/json_has_filesystem.md) for details on known exclusions.

- [x] The library is compiled with 50+ different C++ compilers with different operating systems and platforms,
  including the oldest versions known to compile the library.

    ??? abstract "Compilers used in continuous integration"
      
        | Compiler                                     | Architecture | Operating System                  | CI        |
        |----------------------------------------------|--------------|-----------------------------------|-----------|
        | AppleClang 16.0.0.16000026; Xcode 16         | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
        | AppleClang 16.0.0.16000026; Xcode 16.1       | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
        | AppleClang 16.0.0.16000026; Xcode 16.2       | arm64        | macOS 15.2 (Sequoia)              | GitHub    |
        | AppleClang 17.0.0.17000013; Xcode 16.3       | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
        | AppleClang 17.0.0.17000013; Xcode 16.4       | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
        | AppleClang 17.0.0.17000319; Xcode 26.0.1     | arm64        | macOS 15.5 (Sequoia)              | GitHub    |
        | AppleClang 17.0.0.17000404; Xcode 26.1.1     | arm64        | macOS 15.7.9 (Sequoia)            | GitHub    |
        | AppleClang 17.0.0.17000603; Xcode 26.2       | arm64        | macOS 15.7.9 (Sequoia)            | GitHub    |
        | AppleClang 17.0.0.17000604; Xcode 26.3       | arm64        | macOS 15.7.9 (Sequoia)            | GitHub    |
        | AppleClang 21.0.0.21000099; Xcode 26.4.1     | arm64        | macOS 26.6.2 (Tahoe)              | GitHub    |
        | AppleClang 21.0.0.21000101; Xcode 26.5       | arm64        | macOS 26.6.2 (Tahoe)              | GitHub    |
        | AppleClang 21.0.0.21000101; Xcode 26.6       | arm64        | macOS 26.6.2 (Tahoe)              | GitHub    |
        | Clang 3.4.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 3.5.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 3.6.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 3.7.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 3.8.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 3.9.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 4.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 5.0.2                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 6.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 7.1.0                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 8.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 9.0.1                                  | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 10.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 11.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 11.1.0                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 12.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 12.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 13.0.1 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 13.0.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 14.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 14.0.6 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 15.0.7                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 15.0.7 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 16.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 16.0.6 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 17.0.6                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 18.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 18.1.8 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 19.1.5 with MSVC-like command-line     | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 19.1.7                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 19.1.7 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 20.1.1                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 20.1.8 with GNU-like command-line      | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | Clang 21.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | Clang 22.1.8                                 | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | CUDA 11.8.0 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
        | CUDA 12.1.1 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
        | CUDA 12.6.3 (nvcc)                           | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
        | Emscripten 4.0.6                             | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 4.8.5                                    | x86_64       | Ubuntu 20.04 LTS                  | GitHub    |
        | GNU 4.9.3                                    | x86_64       | Ubuntu 20.04 LTS                  | GitHub    |
        | GNU 5.5.0                                    | x86_64       | Ubuntu 20.04 LTS                  | GitHub    |
        | GNU 6.4.0                                    | x86_64       | Ubuntu 20.04 LTS                  | GitHub    |
        | GNU 7.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 8.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 9.3.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 9.4.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 9.5.0                                    | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 10.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 11.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 11.5.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 12.2.0 (MinGW-W64 i686-ucrt-posix-dwarf) | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | GNU 12.2.0 (MinGW-W64 x86_64-ucrt-posix-seh) | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | GNU 12.4.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 13.3.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 14.2.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 15.1.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 16.2.0                                   | x86_64       | Ubuntu 22.04.1 LTS                | GitHub    |
        | GNU 16.1.0                                   | arm64        | Ubuntu 24.04                      | GitHub    |
        | icpc (ICC) 2021.10.0 20230609                | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
        | icpx (Intel oneAPI DPC++/C++) 2025.3.2       | x86_64       | Ubuntu 24.04 LTS                  | GitHub    |
        | nvc++ (NVIDIA HPC SDK) 25.5-0                | x86_64       | Ubuntu 22.04 LTS                  | GitHub    |
        | MSVC 19.0.24241.7                            | x86          | Windows 8.1                       | AppVeyor  |
        | MSVC 19.16.27035.0                           | x86          | Windows-10 (Build 14393)          | AppVeyor  |
        | MSVC 19.29.30157.0                           | x86          | Windows-10 (Build 17763)          | AppVeyor  |
        | MSVC 19.44.35207.0                           | arm64        | Windows 11 (Build 26200)          | GitHub    |
        | MSVC 19.44.35214.0                           | x86          | Windows Server 2022 (Build 20348) | GitHub    |
        | MSVC 19.44.35214.0                           | x86_64       | Windows Server 2022 (Build 20348) | GitHub    |
        | MSVC 19.51.36231.0                           | x86          | Windows Server 2025 (Build 26100) | GitHub    |
        | MSVC 19.51.36231.0                           | x86_64       | Windows Server 2025 (Build 26100) | GitHub    |

- [x] The library is compiled with all C++ language revisions (C++11, C++14, C++17, C++20, C++23, and C++26) to detect
  and fix language deprecations early.
- [x] The library is checked for compiler warnings:
  - On Clang, `-Weverything` is used with 7 exceptions.

    ??? abstract "Clang warnings"

        ```cmake
        # Ignored Clang warnings:
        # -Wno-c++98-compat               The library targets C++11.
        # -Wno-c++98-compat-pedantic      The library targets C++11.
        # -Wno-deprecated-declarations    The library contains annotations for deprecated functions.
        # -Wno-padded                     We do not care about padding warnings.
        # -Wno-covered-switch-default     All switches list all cases and a default case.
        # -Wno-c2y-extensions             Clang 22.1 diagnoses __COUNTER__ as a C2y extension, also in
        #                                 C++ mode. The library does not use __COUNTER__; the warnings
        #                                 all come from vendored Doctest (SECTION/TEST_CASE macros).
        # -Wno-unsafe-buffer-usage        Pervasive: the library's own low-level numeric/buffer code
        #                                 (to_chars, serializer, lexer, binary reader/writer, input
        #                                 adapters, json_pointer) plus vendored Doctest itself (~208
        #                                 distinct sites measured 2026-07-08 on clang trunk) all use
        #                                 raw pointer arithmetic / libc string calls by necessity.
        
        set(CLANG_CXXFLAGS
            -Werror
            -Weverything
            -Wno-c++98-compat
            -Wno-c++98-compat-pedantic
            -Wno-deprecated-declarations
            -Wno-padded
            -Wno-covered-switch-default
            -Wno-c2y-extensions
            -Wno-unsafe-buffer-usage
        )
        
        ```

  - On GCC, 300+ warnings are enabled with 8 exceptions.

    ??? abstract "GCC warnings"

        ```cmake
        # Warning flags determined for GCC 16.2.0 with https://github.com/nlohmann/gcc_flags:
        # Ignored GCC warnings:
        # -Wno-abi-tag           We do not care about ABI tags.
        # -Wno-aggregate-return  The library uses aggregate returns.
        # -Wno-long-long         The library uses the long long type to interface with system functions.
        # -Wno-namespaces        The library uses namespaces.
        # -Wno-nrvo              Doctest triggers this warning.
        # -Wno-padded            We do not care about padding warnings.
        # -Wno-system-headers    We do not care about warnings in system headers.
        # -Wno-templates         The library uses templates.
        
        set(GCC_CXXFLAGS
            -pedantic
            -Werror
            --all-warnings
            --extra-warnings
            -W
            -WNSObject-attribute
            -Wabbreviated-auto-in-template-arg
            -Wabi
            -Wno-abi-tag
            -Waddress
            -Waddress-of-packed-member
            -Wno-aggregate-return
            -Waggressive-loop-optimizations
            -Waligned-new=all
            -Wall
            -Walloc-size
            -Walloc-zero
            -Walloca
            -Wanalyzer-allocation-size
            -Wanalyzer-deref-before-check
            -Wanalyzer-double-fclose
            -Wanalyzer-double-free
            -Wanalyzer-exposure-through-output-file
            -Wanalyzer-exposure-through-uninit-copy
            -Wanalyzer-fd-access-mode-mismatch
            -Wanalyzer-fd-double-close
            -Wanalyzer-fd-leak
            -Wanalyzer-fd-phase-mismatch
            -Wanalyzer-fd-type-mismatch
            -Wanalyzer-fd-use-after-close
            -Wanalyzer-fd-use-without-check
            -Wanalyzer-file-leak
            -Wanalyzer-free-of-non-heap
            -Wanalyzer-imprecise-fp-arithmetic
            -Wanalyzer-infinite-loop
            -Wanalyzer-infinite-recursion
            -Wanalyzer-jump-through-null
            -Wanalyzer-malloc-leak
            -Wanalyzer-mismatching-deallocation
            -Wanalyzer-null-argument
            -Wanalyzer-null-dereference
            -Wanalyzer-out-of-bounds
            -Wanalyzer-overlapping-buffers
            -Wanalyzer-possible-null-argument
            -Wanalyzer-possible-null-dereference
            -Wanalyzer-putenv-of-auto-var
            -Wanalyzer-shift-count-negative
            -Wanalyzer-shift-count-overflow
            -Wanalyzer-stale-setjmp-buffer
            -Wanalyzer-symbol-too-complex
            -Wanalyzer-tainted-allocation-size
            -Wanalyzer-tainted-array-index
            -Wanalyzer-tainted-assertion
            -Wanalyzer-tainted-divisor
            -Wanalyzer-tainted-offset
            -Wanalyzer-tainted-size
            -Wanalyzer-throw-of-unexpected-type
            -Wanalyzer-too-complex
            -Wanalyzer-undefined-behavior-ptrdiff
            -Wanalyzer-undefined-behavior-strtok
            -Wanalyzer-unsafe-call-within-signal-handler
            -Wanalyzer-use-after-free
            -Wanalyzer-use-of-pointer-in-stale-stack-frame
            -Wanalyzer-use-of-uninitialized-value
            -Wanalyzer-va-arg-type-mismatch
            -Wanalyzer-va-list-exhausted
            -Wanalyzer-va-list-leak
            -Wanalyzer-va-list-use-after-va-end
            -Wanalyzer-write-to-const
            -Wanalyzer-write-to-string-literal
            -Warith-conversion
            -Warray-bounds=2
            -Warray-compare
            -Warray-parameter
            -Warray-parameter=2
            -Wattribute-alias=2
            -Wattribute-warning
            -Wattributes
            -Wauto-profile
            -Wbidi-chars=any
            -Wbool-compare
            -Wbool-operation
            -Wbuiltin-declaration-mismatch
            -Wbuiltin-macro-redefined
            -Wc++0x-compat
            -Wc++11-compat
            -Wc++11-extensions
            -Wc++14-compat
            -Wc++14-extensions
            -Wc++17-compat
            -Wc++17-extensions
            -Wc++1z-compat
            -Wc++20-compat
            -Wc++20-extensions
            -Wc++23-extensions
            -Wc++26-compat
            -Wc++26-extensions
            -Wc++2a-compat
            -Wcalloc-transposed-args
            -Wcannot-profile
            -Wcast-align
            -Wcast-align=strict
            -Wcast-function-type
            -Wcast-qual
            -Wcast-user-defined
            -Wcatch-value=3
            -Wchanges-meaning
            -Wchar-subscripts
            -Wclass-conversion
            -Wclass-memaccess
            -Wclobbered
            -Wcomma-subscript
            -Wcomment
            -Wcomments
            -Wcomplain-wrong-lang
            -Wconditionally-supported
            -Wconversion
            -Wconversion-null
            -Wcoverage-invalid-line-number
            -Wcoverage-mismatch
            -Wcoverage-too-many-conditions
            -Wcoverage-too-many-paths
            -Wcpp
            -Wctad-maybe-unsupported
            -Wctor-dtor-privacy
            -Wdangling-else
            -Wdangling-pointer=2
            -Wdangling-reference
            -Wdate-time
            -Wdefaulted-function-deleted
            -Wdelete-incomplete
            -Wdelete-non-virtual-dtor
            -Wdeprecated
            -Wdeprecated-copy
            -Wdeprecated-copy-dtor
            -Wdeprecated-declarations
            -Wdeprecated-enum-enum-conversion
            -Wdeprecated-enum-float-conversion
            -Wdeprecated-literal-operator
            -Wdeprecated-openmp
            -Wdeprecated-variadic-comma-omission
            -Wdisabled-optimization
            -Wdiv-by-zero
            -Wdouble-promotion
            -Wduplicated-branches
            -Wduplicated-cond
            -Weffc++
            -Welaborated-enum-base
            -Wempty-body
            -Wendif-labels
            -Wenum-compare
            -Wenum-conversion
            -Wexceptions
            -Wexpansion-to-defined
            -Wexpose-global-module-tu-local
            -Wexternal-tu-local
            -Wextra
            -Wextra-semi
            -Wflex-array-member-not-at-end
            -Wfloat-conversion
            -Wfloat-equal
            -Wformat-diag
            -Wformat-overflow=2
            -Wformat-signedness
            -Wformat-truncation=2
            -Wformat=2
            -Wframe-address
            -Wfree-nonheap-object
            -Wglobal-module
            -Whardened
            -Wheader-guard
            -Whsa
            -Wif-not-aligned
            -Wignored-attributes
            -Wignored-qualifiers
            -Wimplicit-fallthrough=5
            -Winaccessible-base
            -Winfinite-recursion
            -Winherited-variadic-ctor
            -Winit-list-lifetime
            -Winit-self
            -Winline
            -Wint-in-bool-context
            -Wint-to-pointer-cast
            -Winterference-size
            -Winvalid-constexpr
            -Winvalid-imported-macros
            -Winvalid-memory-model
            -Winvalid-offsetof
            -Winvalid-pch
            -Winvalid-utf8
            -Wkeyword-macro
            -Wleading-whitespace=spaces
            -Wliteral-suffix
            -Wlogical-not-parentheses
            -Wlogical-op
            -Wno-long-long
            -Wlto-type-mismatch
            -Wmain
            -Wmaybe-musttail-local-addr
            -Wmaybe-uninitialized
            -Wmemset-elt-size
            -Wmemset-transposed-args
            -Wmisleading-indentation
            -Wmismatched-dealloc
            -Wmismatched-new-delete
            -Wmismatched-tags
            -Wmissing-attributes
            -Wmissing-braces
            -Wmissing-declarations
            -Wmissing-field-initializers
            -Wmissing-include-dirs
            -Wmissing-profile
            -Wmissing-requires
            -Wmissing-template-keyword
            -Wmultichar
            -Wmultiple-inheritance
            -Wmultistatement-macros
            -Wmusttail-local-addr
            -Wno-namespaces
            -Wnarrowing
            -Wnoexcept
            -Wnoexcept-type
            -Wnon-c-typedef-for-linkage
            -Wnon-template-friend
            -Wnon-virtual-dtor
            -Wnonnull
            -Wnonnull-compare
            -Wnormalized=nfkc
            -Wno-nrvo
            -Wnull-dereference
            -Wodr
            -Wold-style-cast
            -Wopenacc-parallelism
            -Wopenmp
            -Wopenmp-simd
            -Woverflow
            -Woverlength-strings
            -Woverloaded-virtual=2
            -Wpacked
            -Wpacked-bitfield-compat
            -Wpacked-not-aligned
            -Wno-padded
            -Wparentheses
            -Wpedantic
            -Wpessimizing-move
            -Wplacement-new=2
            -Wpmf-conversions
            -Wpointer-arith
            -Wpointer-compare
            -Wpragma-once-outside-header
            -Wpragmas
            -Wprio-ctor-dtor
            -Wpsabi
            -Wrange-loop-construct
            -Wredundant-decls
            -Wredundant-move
            -Wredundant-tags
            -Wregister
            -Wreorder
            -Wrestrict
            -Wreturn-local-addr
            -Wreturn-type
            -Wscalar-storage-order
            -Wself-move
            -Wsequence-point
            -Wsfinae-incomplete
            -Wsfinae-incomplete=2
            -Wshadow=compatible-local
            -Wshadow=global
            -Wshadow=local
            -Wshift-count-negative
            -Wshift-count-overflow
            -Wshift-negative-value
            -Wshift-overflow=2
            -Wsign-compare
            -Wsign-conversion
            -Wsign-promo
            -Wsized-deallocation
            -Wsizeof-array-argument
            -Wsizeof-array-div
            -Wsizeof-pointer-div
            -Wsizeof-pointer-memaccess
            -Wstack-protector
            -Wstrict-aliasing
            -Wstrict-aliasing=3
            -Wstrict-null-sentinel
            -Wstrict-overflow
            -Wstrict-overflow=5
            -Wstring-compare
            -Wstringop-overflow
            -Wstringop-overflow=4
            -Wstringop-overread
            -Wstringop-truncation
            -Wsubobject-linkage
            -Wsuggest-attribute=cold
            -Wsuggest-attribute=const
            -Wsuggest-attribute=format
            -Wsuggest-attribute=malloc
            -Wsuggest-attribute=noreturn
            -Wsuggest-attribute=pure
            -Wsuggest-attribute=returns_nonnull
            -Wsuggest-final-methods
            -Wsuggest-final-types
            -Wsuggest-override
            -Wswitch
            -Wswitch-bool
            -Wswitch-default
            -Wswitch-enum
            -Wswitch-outside-range
            -Wswitch-unreachable
            -Wsync-nand
            -Wsynth
            -Wno-system-headers
            -Wtautological-compare
            -Wtemplate-body
            -Wtemplate-id-cdtor
            -Wtemplate-names-tu-local
            -Wno-templates
            -Wterminate
            -Wtrailing-whitespace
            -Wtrampolines
            -Wtrigraphs
            -Wtrivial-auto-var-init
            -Wtsan
            -Wtype-limits
            -Wundef
            -Wunicode
            -Wuninitialized
            -Wunknown-pragmas
            -Wunreachable-code
            -Wunsafe-loop-optimizations
            -Wunused
            -Wunused-but-set-parameter=3
            -Wunused-but-set-variable=3
            -Wunused-const-variable=2
            -Wunused-function
            -Wunused-label
            -Wunused-local-typedefs
            -Wunused-macros
            -Wunused-parameter
            -Wunused-result
            -Wunused-value
            -Wunused-variable
            -Wuse-after-free=3
            -Wuseless-cast
            -Wvarargs
            -Wvariadic-macros
            -Wvector-operation-performance
            -Wvexing-parse
            -Wvirtual-inheritance
            -Wvirtual-move-assign
            -Wvla
            -Wvla-parameter
            -Wvolatile
            -Wvolatile-register-var
            -Wwrite-strings
            -Wxor-used-as-pow
            -Wzero-as-null-pointer-constant
            -Wzero-length-bounds
        )
        
        ```

## C++ standard library compliance

!!! success "Requirement: No prerequisites"

    The library has no prerequisites other than the Standard Template Library (STL).

- [x] The library is compiled and tested with both [libc++](https://libcxx.llvm.org) and
  [libstdc++](https://gcc.gnu.org/onlinedocs/libstdc++/) to detect subtle differences or incompatibilities.
- [x] The code checked with [Include What You Use (IWYU)](https://include-what-you-use.org) that all required standard
  headers are included.
- [x] On Windows, the library is compiled with `<Windows.h>` being included to detect and avoid common bugs (see
  [`unit-windows_h.cpp`](https://github.com/nlohmann/json/blob/develop/tests/src/unit-windows_h.cpp)).
- [x] The library is compiled with Qt's keyword macros (`slots`, `signals`, `emit`, `foreach`, `forever`) being defined
  to make sure it does not use them as identifiers (see
  [`unit-qt_keywords.cpp`](https://github.com/nlohmann/json/blob/develop/tests/src/unit-qt_keywords.cpp)).
- [x] The library is compiled with exceptions disabled to support alternative means of error handling.

## Stable public API

!!! success "Requirement: Stable public API"

    Any change to the library does not break the public API.

- [x] All public API functions are tested with a variety of arguments.
- [x] The library is compiled and tested with different template arguments for number, string, array, and object types.
- [x] Unit tests cover all lines of the code base.
- [x] Every exception of the library is thrown in the test suite, and the error messages and exception ids are checked.

!!! success "Requirement: Complete documentation"

    The public API is extensively documented.

- [x] Every public API function has a dedicated page in the
  [API reference documentation](https://json.nlohmann.me/api/basic_json/) with a self-contained code example.
- [x] All examples in the documentation are tested, and changes in their output are treated as an error.

## Robust input processing

!!! success "Requirement: Standards compliance"

    The library is compliant to JSON as defined in [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259).

- [x] The lexer is tested with all valid Unicode code points and all prefixes of all invalid Unicode code points.
- [x] The parser is tested against extensive correctness suites for JSON compliance.
- [x] In addition, the library is continuously fuzz-tested at [OSS-Fuzz](https://google.github.io/oss-fuzz/) where the
  library is checked against billions of inputs.
- [x] Every crash reported by OSS-Fuzz is fixed together with a unit test that reproduces it, and the fix references
  the OSS-Fuzz issue. The round-trip checks of the fuzzer drivers are also part of the unit tests. See the
  [fuzz testing documentation](https://github.com/nlohmann/json/blob/develop/tests/fuzzing.md#handling-oss-fuzz-reports).

## Static analysis

!!! success "Requirement: State-of-the-art code analysis"

    The code is checked with state-of-the-art static code analysis tools.

- [x] The code is checked with the latest [Clang-Tidy](https://clang.llvm.org/extra/clang-tidy/).

    ??? abstract "Clang-Tidy configuration (.clang-tidy)"

        ```ini
        # Style or vendor rule sets that do not fit a header-only library:
        #   altera-*, fuchsia-*, llvmlibc-*, android-cloexec-fopen, boost-use-ranges, llvm-header-guard,
        #   llvm-include-order, llvm-prefer-static-over-anonymous-namespace, llvm-use-ranges,
        #   misc-use-anonymous-namespace, google-runtime-float, google-runtime-int, hicpp-signed-bitwise,
        #   bugprone-signed-bitwise, hicpp-explicit-conversions, google-explicit-constructor,
        #   cppcoreguidelines-explicit-constructor, misc-explicit-constructor (implicit conversions are the
        #   API), readability-trailing-comma,
        #   hicpp-avoid-goto / cppcoreguidelines-avoid-goto, hicpp-no-array-decay,
        #   hicpp-uppercase-literal-suffix, readability-uppercase-literal-suffix, modernize-use-trailing-return-type.
        # Constructs the library needs on purpose (the library supports C++11 and legacy compilers):
        #   cppcoreguidelines-macro-usage, cppcoreguidelines-avoid-do-while (macros),
        #   cppcoreguidelines-pro-bounds-*, cppcoreguidelines-pro-type-reinterpret-cast,
        #   cppcoreguidelines-pro-type-union-access (parsers, serializers, basic_json's value union),
        #   cppcoreguidelines-avoid-const-or-ref-data-members, cppcoreguidelines-rvalue-reference-param-not-moved,
        #   cppcoreguidelines-avoid-non-const-global-variables, misc-non-private-member-variables-in-classes,
        #   misc-no-recursion (value walks are recursive, bounded by detail::recursion_depth_limit()),
        #   modernize-type-traits, modernize-use-constraints, modernize-use-ranges, modernize-use-std-numbers,
        #   modernize-use-designated-initializers, modernize-use-nodiscard, modernize-concat-nested-namespaces,
        #   readability-redundant-typename, readability-redundant-parentheses,
        #   readability-redundant-access-specifiers, readability-simplify-boolean-expr,
        #   readability-use-concise-preprocessor-directives, modernize-use-string-view,
        #   modernize-use-integer-sign-comparison (needs std::cmp_less; the flagged
        #   static_cast<std::size_t>(end - pos) < n comparisons are deliberate)
        #   (all need a newer standard or compiler than C++11, or would change macro-generated or
        #   deliberately explicit code).
        # Too noisy to be useful (numeric parsing/formatting code, doctest, tests):
        #   bugprone-easily-swappable-parameters, cppcoreguidelines-avoid-magic-numbers, readability-magic-numbers,
        #   readability-identifier-length, readability-function-cognitive-complexity, performance-enum-size,
        #   concurrency-mt-unsafe, misc-confusable-identifiers, misc-include-cleaner (run on its own for
        #   the consumer headers in cmake/ci.cmake).
        # portability-avoid-pragma-once: kept disabled on purpose. #pragma once is accepted
        # by every supported compiler, and tools/amalgamate/amalgamate.py strips it from
        # single_include, so there is nothing left to fix here.
        
        Checks: '*,
        
                 -altera-id-dependent-backward-branch,
                 -altera-struct-pack-align,
                 -altera-unroll-loops,
                 -android-cloexec-fopen,
                 -boost-use-ranges,
                 -bugprone-easily-swappable-parameters,
                 -bugprone-signed-bitwise,
                 -concurrency-mt-unsafe,
                 -cppcoreguidelines-avoid-const-or-ref-data-members,
                 -cppcoreguidelines-avoid-do-while,
                 -cppcoreguidelines-avoid-goto,
                 -cppcoreguidelines-avoid-magic-numbers,
                 -cppcoreguidelines-avoid-non-const-global-variables,
                 -cppcoreguidelines-explicit-constructor,
                 -cppcoreguidelines-macro-usage,
                 -cppcoreguidelines-pro-bounds-avoid-unchecked-container-access,
                 -cppcoreguidelines-pro-bounds-array-to-pointer-decay,
                 -cppcoreguidelines-pro-bounds-constant-array-index,
                 -cppcoreguidelines-pro-bounds-pointer-arithmetic,
                 -cppcoreguidelines-pro-type-reinterpret-cast,
                 -cppcoreguidelines-pro-type-union-access,
                 -cppcoreguidelines-rvalue-reference-param-not-moved,
                 -fuchsia-default-arguments-calls,
                 -fuchsia-default-arguments-declarations,
                 -fuchsia-overloaded-operator,
                 -google-explicit-constructor,
                 -google-runtime-float,
                 -google-runtime-int,
                 -hicpp-avoid-goto,
                 -hicpp-explicit-conversions,
                 -hicpp-no-array-decay,
                 -hicpp-signed-bitwise,
                 -hicpp-uppercase-literal-suffix,
                 -llvm-header-guard,
                 -llvm-include-order,
                 -llvm-prefer-static-over-anonymous-namespace,
                 -llvm-use-ranges,
                 -llvmlibc-*,
                 -misc-use-anonymous-namespace,
                 -misc-confusable-identifiers,
                 -misc-explicit-constructor,
                 -misc-include-cleaner,
                 -misc-no-recursion,
                 -misc-non-private-member-variables-in-classes,
                 -modernize-concat-nested-namespaces,
                 -modernize-type-traits,
                 -modernize-use-constraints,
                 -modernize-use-designated-initializers,
                 -modernize-use-integer-sign-comparison,
                 -modernize-use-nodiscard,
                 -modernize-use-ranges,
                 -modernize-use-string-view,
                 -modernize-use-std-numbers,
                 -modernize-use-trailing-return-type,
                 -performance-enum-size,
                 -portability-avoid-pragma-once,
                 -readability-function-cognitive-complexity,
                 -readability-identifier-length,
                 -readability-magic-numbers,
                 -readability-redundant-access-specifiers,
                 -readability-redundant-parentheses,
                 -readability-redundant-typename,
                 -readability-simplify-boolean-expr,
                 -readability-trailing-comma,
                 -readability-uppercase-literal-suffix,
                 -readability-use-concise-preprocessor-directives'
        
        CheckOptions:
          - key: hicpp-special-member-functions.AllowSoleDefaultDtor
            value: 1
          # clang-tidy 22.1 extended this check to classes and enums; the test files
          # define many such helper types at namespace scope, which is harmless
          - key: misc-use-internal-linkage.AnalyzeTypes
            value: false
        
        WarningsAsErrors: '*'
        
        HeaderFilterRegex: '.*hpp$'
        
        ```

- [x] The code is checked with the latest [Cppcheck](https://cppcheck.sourceforge.io) with all warnings enabled.
- [x] The code is checked with the latest [Clang Static Analyzer](https://clang-analyzer.llvm.org) with 52 enabled
  checkers.
- [x] The code is checked with [Infer](https://fbinfer.com).
- [x] The code is checked with [Codacy](https://app.codacy.com/gh/nlohmann/json/dashboard).
- [x] The code is scanned with [CodeQL](https://codeql.github.com), [Semgrep](https://semgrep.dev), and
  [Flawfinder](https://dwheeler.com/flawfinder/) on every push and pull request and on a schedule; the findings are
  reported to GitHub's code scanning.

## Dynamic analysis

!!! success "Requirement: Correctness"

    The library is checked for memory correctness and absence of undefined behavior.

- [x] The test suite is executed with enabled [runtime assertions](https://json.nlohmann.me/features/assertions/) to
  check invariants and preconditions of functions to detect undefined behavior.
- [x] The test suite is executed with [Valgrind](https://valgrind.org) (Memcheck) to detect memory leaks.
- [x] The test suite is executed with [Sanitizers](https://github.com/google/sanitizers) (address sanitizer, undefined
  behavior sanitizer, integer overflow detection, nullability violations).
- [x] The fuzz targets are run with [CIFuzz](https://google.github.io/oss-fuzz/getting-started/continuous-integration/)
  on every pull request to catch regressions before they are merged.

## Dependencies

!!! success "Requirement: No vulnerable dependencies"

    The library has no dependencies besides the C++ standard library. The tools used to build, test, and document it
    are kept free of known vulnerabilities.

- [x] GitHub Actions are pinned to a commit hash, and the Python packages used by the documentation and the tools are
  pinned to exact versions.
- [x] [Dependabot](https://docs.github.com/en/code-security/dependabot) checks these dependencies daily and proposes
  updates as pull requests.
- [x] Every pull request is checked with the
  [dependency review action](https://github.com/actions/dependency-review-action). A pull request that adds a
  dependency with a known vulnerability of any severity fails this check and is not merged.
- [x] Vulnerability alerts for dependencies are fixed or dismissed with a documented reason before the next release.
  No release is made while such an alert is open.
- [x] Third-party code included in the repository for testing, such as [doctest](https://github.com/doctest/doctest),
  is updated manually.
- [x] The repository is evaluated with the [OpenSSF Scorecard](https://securityscorecards.dev) on a schedule and on
  every push to the default branch, and the results are reported to GitHub's code scanning.

## Style check

!!! success "Requirement: Common code style"

    A common code style is used throughout all code files of the library.

- [x] The code is formatted with [Artistic Style](https://astyle.sourceforge.net) (astyle) against a style configuration
  that is also enforced in the CI.

    ??? abstract "Astyle configuration (tools/astyle/.astylerc)"
      
        ```ini
        # Configuration for Artistic Style
        # see https://astyle.sourceforge.net/astyle.html
        
        #######################
        # Brace Style Options #
        #######################
        
        # use Allman style for braces
        --style=allman
        
        ###############
        # Tab Options #
        ###############
        
        # indent using 4 spaces
        --indent=spaces=4
        
        #######################
        # Indentation Options #
        #######################
        
        # indent access modifiers one half indent
        --indent-modifiers
        
        # indent switch cases to the switch block
        --indent-switches
        
        # indent preprocessor blocks
        --indent-preproc-block
        
        # indent preprocessor defines
        --indent-preproc-define
        
        # indent C++ comments
        --indent-col1-comments
        
        ###################
        # Padding Options #
        ###################
        
        # insert space padding around operators
        --pad-oper
        
        # insert space between if/for/while... and the following parentheses
        --pad-header
        
        # attach the pointer to the variable type (left)
        --align-pointer=type
        
        # attach the reference to the variable type (left)
        --align-reference=type
        
        ######################
        # Formatting Options #
        ######################
        
        # add braces to unbraced one line conditional statements
        --add-braces
        
        # convert tabs to spaces
        --convert-tabs
        
        # closes whitespace between the ending angle brackets of template definitions
        --close-templates
        
        #################
        # Other Options #
        #################
        
        # do not create backup files
        --suffix=none
        
        # preserve the original file date
        --preserve-date
        
        # display only the files that have been formatted
        --formatted
        
        # for the linux (LF) line end style
        --lineend=linux
        
        ```

- [x] The code style is checked with [cpplint](https://github.com/cpplint/cpplint) with 61 enabled rules.

## Simple integration

!!! success "Requirement: Single header"

    The library can be used by adding a single header to a C++ project.

- [x] An amalgamation script is used to check if the source code is exposed as a self-contained single-header file.
- [x] The test suite is checked against the amalgamated source file as well as the individual source file.

!!! success "Requirement: CMake as primary development tool"

    All library functions are exposed and usable by CMake.

- [x] All library options are exposed as [CMake options](https://json.nlohmann.me/integration/cmake/) and tested.
- [x] The library is tested against relevant CMake versions:
  - CMake 3.5 (the earliest supported)
  - CMake 3.31.6 (the latest 3.x release)
  - CMake 4.0.0 (the first 4.x release)
!!! success "Requirement: Other build systems"

    The library can be used with build systems and package managers other than CMake.

- [x] The library can be consumed with [Meson](https://json.nlohmann.me/integration/package_managers/) and the Swift
  Package Manager; the installation with Meson and the resolution of `Package.swift` are tested in the CI.

!!! success "Requirement: Reproducible and verifiable builds"

    The library can be built and tested without network access or a Git checkout, and its licensing is machine-readable.

- [x] The test suite is executed from an exported source tree without the `.git` directory and with the test data
  being available offline.
- [x] The test suite is executed without the tests that change installed files to check that builds are reproducible.
- [x] The repository is checked for compliance with the [REUSE specification](https://reuse.software) so that the
  license and copyright of every file is machine-readable.
- [x] The documentation is built with warnings treated as errors, and its links are checked regularly.
