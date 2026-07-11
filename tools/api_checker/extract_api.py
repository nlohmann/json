#!/usr/bin/env python3
"""Extract the public API surface of nlohmann/json using libclang AST.

This tool derives the public API from C++ semantics (class templates, access specifiers,
namespace scoping) independently of documentation status. The extracted surface is the
source of truth for what is considered "public API" — doc-checking and API diffing are
downstream consumers of this snapshot.

Strategy:
1. Parse include/nlohmann/json.hpp with libclang (with proper system includes)
2. Walk the primary class-template definitions of the 6 known public classes
3. Extract callable members (methods, constructors, destructors, conversion ops) and type aliases
4. Extract free functions/operators in nlohmann:: (excluding detail::)
5. Handle alias-exposed exception types by following the alias to the detail:: definition
6. Normalize away the ABI inline-namespace (json_abi_v3_12_0, json_abi_diag_v3_12_0, etc.)
7. Emit a snapshot with an overload-disambiguating identity key and documentation status

Output includes both public_api (all tracked public entities) and documented_non_public
(entities with @sa comments that are NOT in the public surface — used for validation).
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    from clang import cindex
except ImportError:
    print("Error: libclang not installed. Run: pip install -r tools/api_checker/requirements.txt")
    sys.exit(1)


ABI_TAG_PATTERN = re.compile(r'::json(?:_abi)?[a-z_]*_v\d+_\d+_\d+(?=::|$)')

# Bump whenever a change to this schema, or to the identity-computing algorithm
# (get_signature_text()/get_identity_name()/identity_key()), could alter the 'signature' or
# 'identity_name' text for otherwise-unchanged source. diff_api.py refuses by default to compare
# two surface files with different SURFACE_FORMAT_VERSION -- see diff_api.py and
# tools/api_checker/POLICY.md for why: an earlier, unversioned identity scheme (based on
# libclang's USR) silently corrupted every historical comparison whenever the *unrelated*
# enclosing class template gained a new template parameter, and nothing caught it because there
# was no version to check.
SURFACE_FORMAT_VERSION = 2


def strip_abi_tag(text: str) -> str:
    """Remove ABI inline-namespace from a qualified name or type string."""
    return ABI_TAG_PATTERN.sub('', text)


_FILE_CONTENT_CACHE = {}


def _read_file_cached(path: str) -> str:
    if path not in _FILE_CONTENT_CACHE:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                _FILE_CONTENT_CACHE[path] = f.read()
        except OSError:
            _FILE_CONTENT_CACHE[path] = ''
    return _FILE_CONTENT_CACHE[path]


def get_signature_text(cursor) -> str:
    """The normalized source text of a declaration's own signature -- template header, return
    type, name, full parameter list, and trailing cv/ref/noexcept qualifiers -- stopping before
    the function body ('{') or at the terminating ';'/'= default;'/'= 0;'. Never includes the
    body, so implementation-only changes don't affect identity.

    Reads raw source text via cursor.extent's byte offsets rather than cursor.get_tokens():
    the latter was found to silently return zero tokens whenever a cursor's extent starts
    exactly at an unexpanded macro invocation (confirmed empirically for basic_json's four
    binary() overloads and iterator_wrapper(), both preceded by JSON_HEDLEY_WARN_UNUSED_RESULT
    -- a known class of libclang tokenizer edge case, not specific to this codebase). Raw text
    also avoids cursor.get_arguments()/cursor.type.spelling, which were separately found
    empty/unreliable for some FUNCTION_TEMPLATE cursors with complex trailing
    noexcept(noexcept(...))/decltype(...) clauses (adl_serializer::from_json). Source text is
    what's actually written (declared names like "ValueType", never a resolved
    "basic_json<T0,...,T10>"), so it's immune to the enclosing class's template arity too --
    see identity_key()'s docstring for why that matters.

    Comments are stripped while scanning. Without this, a purely cosmetic NOLINT annotation
    added mid-signature (e.g. `KeyType&& key) // NOLINT(...)`  before the body's '{') would
    change the captured text -- confirmed empirically via a real nlohmann/json release
    (v3.11.2 -> v3.11.3 added such NOLINT comments to several ordered_map methods and to
    basic_json's swap(), with no other change, and diff_api.py reported all of them as
    "changed overloads").
    """
    start = cursor.extent.start
    end = cursor.extent.end
    if not start.file:
        return ''
    content = _read_file_cached(start.file.name)
    if not content:
        return ''
    raw = content[start.offset:end.offset]

    paren_depth = 0
    angle_depth = 0
    seen_param_list_close = False
    out = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch == '/' and i + 1 < n and raw[i + 1] == '/':
            i = raw.find('\n', i)
            if i == -1:
                break
            continue
        if ch == '/' and i + 1 < n and raw[i + 1] == '*':
            end_comment = raw.find('*/', i + 2)
            i = n if end_comment == -1 else end_comment + 2
            continue
        if ch == '{' and paren_depth == 0 and angle_depth == 0:
            break
        if ch == ';' and paren_depth == 0 and angle_depth == 0:
            out.append(ch)
            break
        # A bare ':' after the parameter list has closed starts a constructor's
        # member-initializer-list ("basic_json(...) : m_data(v) { ... }") -- that's
        # implementation (which members get initialized how), not public signature, so stop
        # before it. Guarded by seen_param_list_close so this doesn't misfire on a ':' that's
        # actually part of a preceding "::" scope-resolution token in the return type/params.
        if (ch == ':' and seen_param_list_close and paren_depth == 0 and angle_depth == 0
                and (i == 0 or raw[i - 1] != ':') and (i + 1 >= n or raw[i + 1] != ':')):
            break
        if ch == '(':
            paren_depth += 1
        elif ch == ')':
            paren_depth = max(0, paren_depth - 1)
            if paren_depth == 0:
                seen_param_list_close = True
        elif ch == '<':
            angle_depth += 1
        elif ch == '>' and angle_depth > 0:
            angle_depth -= 1
        out.append(ch)
        i += 1

    sig = re.sub(r'\s+', ' ', ''.join(out)).strip()
    return strip_abi_tag(sig)


def get_identity_name(cursor, scope: str) -> str:
    """The name component of a cursor's identity -- usually cursor.spelling, but not for
    CONSTRUCTOR/DESTRUCTOR cursors, or FUNCTION_TEMPLATE cursors that are themselves templated
    constructors (e.g. `template<typename CompatibleType> basic_json(CompatibleType&& val)`,
    which libclang represents as FUNCTION_TEMPLATE, not CONSTRUCTOR).

    libclang's cursor.spelling for those renders the *enclosing class's full template argument
    list* (e.g. "basic_json<ObjectType, ..., CustomBaseClass>"), not just "basic_json". Using it
    as-is for identity would reintroduce class-arity sensitivity (see identity_key()'s docstring
    for why that's a problem) just for constructors specifically. Detected by checking whether
    cursor.spelling equals or starts with "<ClassName><" -- the class's own bare name, the last
    segment of scope. A canonical placeholder ("(constructor)"/"(destructor)") is substituted for
    identity purposes; callers still use cursor.spelling as-is for human-readable display fields
    (name/pretty_signature), where the full templated name is informative rather than noisy.
    """
    class_bare_name = scope.rsplit('::', 1)[-1]
    is_constructor_like = (
        cursor.kind == cindex.CursorKind.CONSTRUCTOR
        or (cursor.kind == cindex.CursorKind.FUNCTION_TEMPLATE
            and (cursor.spelling == class_bare_name or cursor.spelling.startswith(class_bare_name + '<')))
    )
    if is_constructor_like:
        return '(constructor)'
    if cursor.kind == cindex.CursorKind.DESTRUCTOR:
        return '(destructor)'
    return cursor.spelling


def identity_key(cursor, scope: str) -> str:
    """A stable, overload-disambiguating key, used internally during extraction to prevent two
    distinct entries from silently colliding in the in-memory api_dict. Two prior approaches were
    tried and found broken:

    1. {scope, name, kind, params} from cursor.get_arguments() alone: silently collided for
       overload sets differentiated only by constness, ref-qualifiers, or SFINAE constraints
       rather than parameter types -- e.g. basic_json's two zero-argument get() overloads (one
       const, one not) both produced params=[] and overwrote each other in the output dict. A
       full scan found 59 such silent overwrites across 27 colliding names. Extending this
       approach with is_const/is_static/ref-qualifier flags fixed most of these but not all --
       adl_serializer::from_json's two overloads and basic_json's two erase(iterator) overloads
       still collided, because get_arguments() returns [] for them (see get_signature_text()'s
       docstring) and their template-parameter lists happen to read identically too.
    2. libclang's USR: correctly disambiguates every overload (it encodes the full mangled
       signature) but also encodes the *enclosing class template's own arity* into every
       member's USR. Confirmed empirically: basic_json gaining a defaulted CustomBaseClass
       template parameter between v3.11.2 and v3.11.3 (a backward-compatible change) changed
       literally every basic_json member's USR, which made diff_api.py report ~228/330 entries
       as "changed" for a release with zero real breaking changes among them. Reconstructing
       "the member's own identity" by string-surgery on USR text was rejected: clang's USR
       grammar is undocumented and not a stable contract for this kind of manipulation.

    This key avoids both failure modes: scope is passed in (derived from get_qualified_name(),
    never from USR), and get_signature_text() reads the declaration as literally written in
    source, which never encodes the enclosing class's resolved template arguments and reliably
    disambiguates every case found so far (SFINAE-only overloads, overloads get_arguments()
    can't see, and simple parameter-type differences alike).

    Known limitation: because the signature text includes parameter *names*, not just types, a
    pure parameter rename (no type/constraint change) would look like a "changed" entry to
    diff_api.py. Accepted as a much smaller and rarer source of noise than either bug above --
    see POLICY.md.

    NOTE: this opaque joined string is only used as a dict key during extraction. The persisted
    --surface-output format (see main()) stores scope/identity_name/kind/signature as separate,
    explicit fields instead -- a human or `git diff` should never need to decode this string.
    """
    return '\x1f'.join([scope, get_identity_name(cursor, scope), cursor.kind.name, get_signature_text(cursor)])


def get_repo_root():
    """Find the repository root via git, so location paths are deterministic regardless of invoking CWD."""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--show-toplevel'],
            capture_output=True, text=True, check=True, timeout=10
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


REPO_ROOT = get_repo_root()


def canonicalize_path(file_path: str) -> str:
    """Make a file path deterministic: absolute, then relative to the repo root."""
    if not file_path:
        return 'unknown'
    abs_path = os.path.abspath(file_path)
    if REPO_ROOT:
        return os.path.relpath(abs_path, REPO_ROOT)
    return abs_path


def cursor_location(cursor) -> str:
    """Build a canonical 'path:line' string for a cursor, or 'unknown' if it has no file."""
    if cursor.location and cursor.location.file:
        return f"{canonicalize_path(cursor.location.file.name)}:{cursor.location.line}"
    return "unknown"


def get_system_includes(compiler='clang++'):
    """Discover system include paths by parsing clang++ -E -x c++ -v /dev/null output."""
    try:
        result = subprocess.run(
            [compiler, '-E', '-x', 'c++', '-v', '/dev/null'],
            capture_output=True, text=True, check=True, timeout=10
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
        print(f"Warning: Failed to discover system includes via '{compiler}': {e}")
        return []

    stderr = result.stderr
    in_block = False
    paths = []
    for line in stderr.splitlines():
        if line.strip() == '#include <...> search starts here:':
            in_block = True
            continue
        if line.strip() == 'End of search list.':
            in_block = False
            continue
        if in_block:
            # Strip trailing annotations like "(framework directory)"
            path = line.strip().split()[0] if line.strip() else ''
            if path:
                paths.append(path)

    return [f'-isystem{p}' for p in paths]


def setup_libclang():
    """Locate and set up libclang library."""
    possible_paths = [
        '/opt/homebrew/opt/llvm/lib/libclang.dylib',  # macOS
        '/usr/local/opt/llvm/lib/libclang.dylib',      # macOS alt
        '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib',
        '/usr/lib/libclang.so',  # Linux
        '/usr/lib/x86_64-linux-gnu/libclang.so',       # Linux
    ]

    for path in possible_paths:
        if os.path.exists(path):
            try:
                cindex.conf.set_library_file(path)
                return True
            except Exception:
                continue

    try:
        filename = cindex.conf.get_filename()
        if filename:
            cindex.conf.set_library_file(filename)
            return True
    except Exception:
        pass

    return False


def extract_sa_url(raw_comment: str) -> str | None:
    """Extract @sa URL from a Doxygen comment."""
    if not raw_comment:
        return None
    match = re.search(r'@sa\s+(https://[^\s]+)', raw_comment)
    return match.group(1) if match else None


def get_qualified_name(cursor) -> str:
    """Get fully qualified name by walking semantic_parent chain."""
    parts = []
    c = cursor
    while c and c.kind != cindex.CursorKind.TRANSLATION_UNIT:
        if c.kind == cindex.CursorKind.NAMESPACE:
            # Skip ABI inline-namespace cursors
            if not ABI_TAG_PATTERN.search(f'::{c.spelling}'):
                parts.append(c.spelling)
        elif c.spelling:
            parts.append(c.spelling)
        c = c.semantic_parent
    return '::'.join(reversed(parts)) if parts else ''


def walk_class_template(cursor, public_classes: set, api_dict: dict, documented_non_public: list):
    """Walk a class template's members: extract public callable/type-tier entities, and flag
    any non-public member that surprisingly carries a real @sa URL (a genuine documentation leak)."""
    if cursor.kind not in (cindex.CursorKind.CLASS_TEMPLATE, cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL):
        return
    if cursor.spelling not in public_classes or not cursor.is_definition():
        return

    scope = strip_abi_tag(get_qualified_name(cursor))
    location = cursor_location(cursor)

    # Exemption list: STL-container-named-requirement aliases that don't require @sa
    stl_exempt = {'value_type', 'reference', 'const_reference', 'pointer', 'const_pointer',
                  'iterator', 'const_iterator', 'reverse_iterator', 'const_reverse_iterator',
                  'difference_type', 'size_type', 'allocator_type', 'key_type', 'mapped_type'}

    for child in cursor.get_children():
        is_public = not hasattr(child, 'access_specifier') or str(child.access_specifier) == 'AccessSpecifier.PUBLIC'

        if not is_public:
            # documented_non_public tracks entities NOT part of the public surface that
            # nonetheless carry a real @sa URL -- a genuine documentation leak, not "any
            # public member missing @sa" (that's what check_docs.py's missing-@sa check is for).
            leaked_url = extract_sa_url(child.raw_comment)
            if leaked_url:
                documented_non_public.append({
                    'location': cursor_location(child),
                    'raw_comment_excerpt': (child.raw_comment or '')[:100],
                    'reason': f'{child.kind.name} "{child.spelling}" is non-public but has @sa: {leaked_url}'
                })
            continue

        # Callable tier: methods, constructors, destructors, conversion ops, function templates
        if child.kind in (cindex.CursorKind.CXX_METHOD, cindex.CursorKind.CONSTRUCTOR,
                         cindex.CursorKind.DESTRUCTOR, cindex.CursorKind.CONVERSION_FUNCTION,
                         cindex.CursorKind.FUNCTION_TEMPLATE):
            key = identity_key(child, scope)
            doc_url = extract_sa_url(child.raw_comment)
            api_dict[key] = {
                'scope': scope,
                'name': child.spelling,
                'identity_name': get_identity_name(child, scope),
                'kind': child.kind.name,
                'tier': 'callable',
                'signature': get_signature_text(child),
                'location': cursor_location(child),
                'doc_url': doc_url,
                'has_sa': doc_url is not None,
                'pretty_signature': f"{scope}::{child.spelling}",
            }

        # Type tier: TYPE_ALIAS_DECL
        elif child.kind == cindex.CursorKind.TYPE_ALIAS_DECL:
            name = child.spelling
            tier = 'type_exempt' if name in stl_exempt else 'type'

            # Try to follow the alias to find @sa on the underlying declaration
            doc_url = extract_sa_url(child.raw_comment)
            underlying_location = None
            if not doc_url and hasattr(child, 'underlying_typedef_type'):
                try:
                    underlying_decl = child.underlying_typedef_type.get_declaration()
                    if underlying_decl and underlying_decl.raw_comment:
                        doc_url = extract_sa_url(underlying_decl.raw_comment)
                        if underlying_decl.location.file:
                            underlying_location = cursor_location(underlying_decl)
                except Exception:
                    pass

            key = identity_key(child, scope)
            api_dict[key] = {
                'scope': scope,
                'name': name,
                'identity_name': get_identity_name(child, scope),
                'kind': 'TYPE_ALIAS_DECL',
                'tier': tier,
                'signature': get_signature_text(child),
                'location': location,
                'doc_url': doc_url,
                'has_sa': doc_url is not None,
                'pretty_signature': f"{scope}::{name}",
            }
            if underlying_location:
                api_dict[key]['resolved_via_alias_to'] = underlying_location


def walk_ast(cursor, public_classes: set, api_dict: dict, documented_non_public: list):
    """Recursively walk AST."""
    # Check if this is one of the six public class templates
    if cursor.kind in (cindex.CursorKind.CLASS_TEMPLATE, cindex.CursorKind.CLASS_DECL, cindex.CursorKind.STRUCT_DECL):
        if cursor.spelling in public_classes:
            walk_class_template(cursor, public_classes, api_dict, documented_non_public)

    # Extract free functions (not nested in a class)
    elif cursor.kind == cindex.CursorKind.FUNCTION_DECL:
        # Check it's in nlohmann namespace, not detail/std
        parent = cursor.semantic_parent
        if parent and parent.kind == cindex.CursorKind.NAMESPACE:
            ns_name = parent.spelling
            if ns_name == 'nlohmann' or (parent.semantic_parent and parent.semantic_parent.kind == cindex.CursorKind.NAMESPACE and
                                         parent.semantic_parent.spelling == 'nlohmann'):
                # This is a free function in nlohmann (or a subnamespace like json_literals)
                if 'detail' not in ns_name and 'std' not in ns_name:
                    # get_qualified_name(parent), not get_qualified_name(cursor) -- the latter
                    # would include the function's own name as the last segment (cursor is the
                    # function itself), producing a bogus scope like "nlohmann::operator==" and
                    # a doubled pretty_signature "nlohmann::operator==::operator==".
                    scope = strip_abi_tag(get_qualified_name(parent))
                    key = identity_key(cursor, scope)
                    doc_url = extract_sa_url(cursor.raw_comment)
                    api_dict[key] = {
                        'scope': scope,
                        'name': cursor.spelling,
                        'identity_name': get_identity_name(cursor, scope),
                        'kind': 'FUNCTION_DECL',
                        'tier': 'callable',
                        'signature': get_signature_text(cursor),
                        'location': cursor_location(cursor),
                        'doc_url': doc_url,
                        'has_sa': doc_url is not None,
                        'pretty_signature': f"{scope}::{cursor.spelling}",
                    }

    # Recurse into container types
    for child in cursor.get_children():
        walk_ast(child, public_classes, api_dict, documented_non_public)


def write_surface(api_dict: dict, output_path: str, extracted_from: str, extra_meta: dict | None = None):
    """Write the minimal, location/doc-independent API surface: a format_version-tagged, sorted
    list of self-describing records (scope, kind, name, identity_name, tier, signature,
    pretty_signature) -- no opaque joined key, no location, no doc_url.

    This is the file meant to be committed and diffed release-to-release (see
    tools/api_checker/README.md and POLICY.md): 'signature'/'identity_name' are the same values
    identity_key() joins into one opaque string for internal use during extraction, but exposed
    here as separate fields so the file is self-describing -- a human or `git diff` can see
    exactly what changed without decoding anything (see identity_key()'s docstring).

    extra_meta lets callers (e.g. snapshot_release.py, writing a per-release historical record)
    add richer, immutable provenance (ref/commit/generated_at) beyond what a live, repeatedly-
    regenerated snapshot should carry -- see SURFACE_FORMAT_VERSION's docstring for why the live
    file deliberately omits a timestamp.
    """
    records = [
        {
            'scope': entry['scope'],
            'kind': entry['kind'],
            'name': entry['name'],
            'identity_name': entry['identity_name'],
            'tier': entry['tier'],
            'signature': entry['signature'],
            'pretty_signature': entry['pretty_signature'],
        }
        for entry in api_dict.values()
    ]
    records.sort(key=lambda r: (r['scope'], r['name'], r['kind'], r['signature']))

    meta = {'extracted_from': extracted_from}
    if extra_meta:
        meta.update(extra_meta)

    output = {
        'format_version': SURFACE_FORMAT_VERSION,
        'meta': meta,
        'public_api': records,
    }
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2, sort_keys=True)
        f.write('\n')


def run_self_test():
    """Test ABI-tag stripping."""
    tests = [
        ('nlohmann::json_abi_v3_12_0::basic_json::parse', 'nlohmann::basic_json::parse'),
        ('nlohmann::json_abi_diag_v3_12_0::basic_json::dump', 'nlohmann::basic_json::dump'),
        ('nlohmann::json_abi_diag_ldvcmp_v3_11_2::basic_json::get', 'nlohmann::basic_json::get'),
        # The ABI tag as the *last* segment (no following '::') -- the scope of a free function
        # whose direct parent is the ABI-tagged namespace itself, e.g. nlohmann::operator==.
        # A regression: an earlier version of this pattern required a trailing '::' via a
        # lookahead, so it silently failed to strip exactly this case, and diff_api.py reported
        # every free comparison operator as removed-and-readded on every ABI-tag version bump.
        ('nlohmann::json_abi_v3_11_3', 'nlohmann'),
        # v3.11.0/v3.11.1 used "json_vMAJOR_MINOR_PATCH" (no "_abi" segment) before the tag was
        # renamed to "json_abi_v..." in v3.11.2. A regression: an earlier version of this pattern
        # hard-required the literal "_abi" segment, so it silently failed to strip this older
        # form, making diff_api.py report ~100% of the API as removed-and-readded across
        # v3.10.5->v3.11.0->v3.11.1->v3.11.2 (confirmed against the real backfilled history).
        ('nlohmann::json_v3_11_0::basic_json::parse', 'nlohmann::basic_json::parse'),
    ]
    for input_str, expected in tests:
        result = strip_abi_tag(input_str)
        if result != expected:
            print(f"FAIL: strip_abi_tag('{input_str}') = '{result}', expected '{expected}'")
            return False
    print("Self-test passed: ABI-tag stripping works correctly")
    return True


def main():
    parser = argparse.ArgumentParser(description='Extract public API surface from nlohmann/json')
    parser.add_argument('--header', default='include/nlohmann/json.hpp',
                       help='Path to header file to analyze')
    parser.add_argument('--include', default='include',
                       help='Include path for parsing')
    parser.add_argument('--output', default='api_snapshot.json',
                       help='Output file for the full API snapshot (includes source location and '
                            'documentation status -- for check_docs.py; not meant to be committed, '
                            'since location/doc-link churn would make every regeneration look like '
                            'an API change)')
    parser.add_argument('--surface-output', default=None,
                       help='Output file for the minimal API surface (identity only: scope, name, '
                            'kind, tier, pretty_signature -- no location or doc_url). This is the '
                            'file meant to be committed and diffed release-to-release, since it is '
                            'unaffected by unrelated code motion or documentation-site restructuring.')
    parser.add_argument('--self-test', action='store_true',
                       help='Run self-tests and exit')
    parser.add_argument('--extra-isystem', action='append', default=[],
                       help='Extra -isystem include path (repeatable)')

    args = parser.parse_args()

    if args.self_test:
        sys.exit(0 if run_self_test() else 1)

    if not setup_libclang():
        print("Error: Could not locate libclang library")
        sys.exit(1)

    if not os.path.exists(args.header):
        print(f"Error: Header file not found: {args.header}")
        sys.exit(1)

    print(f"Extracting API from {args.header}...")

    # Discover system includes
    sys_includes = get_system_includes()
    if not sys_includes:
        print("Warning: Could not discover system includes via clang++")

    # Build parse arguments
    parse_args = [
        f'-I{args.include}',
        '-std=c++17',
        '-x', 'c++',
        '-fparse-all-comments',
    ] + sys_includes + [f'-isystem{path}' for path in args.extra_isystem]

    # Parse
    index = cindex.Index.create()
    tu = index.parse(args.header, parse_args,
                    options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

    # Check for errors
    errors = [d for d in tu.diagnostics if d.severity >= cindex.Diagnostic.Error]
    if errors:
        print("Parse errors encountered:")
        for diag in errors[:10]:
            print(f"  {diag}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more")
        sys.exit(1)

    # Extract API
    public_classes = {'basic_json', 'adl_serializer', 'byte_container_with_subtype',
                     'json_pointer', 'json_sax', 'ordered_map'}
    api_dict = {}
    documented_non_public = []

    walk_ast(tu.cursor, public_classes, api_dict, documented_non_public)

    # Output. Deliberately no timestamp here: this file is meant to be committed and diffed
    # (see tools/api_checker/README.md), so its content must be a pure function of the source
    # tree -- a generated-at timestamp would make every regeneration look like a diff.
    output = {
        'meta': {
            'extracted_from': canonicalize_path(os.path.abspath(args.header)),
        },
        'public_api': api_dict,
        'documented_non_public': documented_non_public,
    }

    with open(args.output, 'w') as f:
        json.dump(output, f, indent=2, sort_keys=True)
        f.write('\n')

    print(f"Found {len(api_dict)} public API entries")
    if documented_non_public:
        print(f"Found {len(documented_non_public)} entities with @sa outside the public surface")
    print(f"Wrote API snapshot to {args.output}")

    if args.surface_output:
        write_surface(api_dict, args.surface_output, canonicalize_path(os.path.abspath(args.header)))
        print(f"Wrote API surface (location/doc-independent) to {args.surface_output}")


if __name__ == '__main__':
    main()
