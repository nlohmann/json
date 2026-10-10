#!/usr/bin/env python3

"""Generate the Dash docset search index from the mkdocs sources."""

import argparse
import glob
import hashlib
import html
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import urllib.parse
import urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MKDOCS_YML = os.path.join(HERE, '..', 'mkdocs', 'mkdocs.yml')
PAGES = os.path.join(HERE, '..', 'mkdocs', 'docs')

# api pages whose (name, type) cannot be derived by the heuristics
OVERRIDES = {
}

DOCSET = 'JSON_for_Modern_C++.docset'
TITLE_SUFFIX = ' - JSON for Modern C++</title>'

# CSS rules appended to the stylesheet: hide navigation items and fix spacing
# hide the navigation (the documentation browser has its own); Material's class selectors would win over element
# selectors, hence the classes and !important
CSS_PATCH = (
    '\n\n.md-header, .md-footer, .md-tabs, .md-sidebar--primary, .md-content__button { display: none !important; }'
    '\n\n.md-sidebar--secondary, .md-main__inner { top: 0 !important; margin-top: 0 !important; }'
)

USER_AGENT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
              '(KHTML, like Gecko) Chrome/124.0 Safari/537.36')
CONTENT_TYPE_EXT = {'image/svg+xml': '.svg', 'image/png': '.png', 'image/jpeg': '.jpg',
                    'image/gif': '.gif', 'image/webp': '.webp'}

# remote loads that are allowed to remain (URL -> reason)
ALLOWED_REMOTE = {
    # Material only loads this polyfill if the browser has no ResizeObserver
    'https://unpkg.com/resize-observer-polyfill': 'fallback for browsers without ResizeObserver',
}

problems = []


def problem(page, reason) -> None:
    """Record a problem; all problems are reported at the end."""
    problems.append(f'generate_docset.py: {page}: {reason}')


class Loader(yaml.SafeLoader):
    """YAML loader that tolerates the custom tags used in mkdocs.yml."""


Loader.add_multi_constructor('', lambda loader, suffix, node: None)


def walk_nav(items, groups=()):
    """Yield (group titles, nav title or None, md path) for all nav leaves."""
    for item in items:
        if isinstance(item, str):
            yield list(groups), None, item
        elif isinstance(item, dict):
            for title, value in item.items():
                if isinstance(value, list):
                    yield from walk_nav(value, groups + (str(title),))
                else:
                    yield list(groups), str(title), value


def page_path(md_path) -> str:
    """Map a markdown path to the HTML path of the rendered page."""
    if md_path.endswith('/index.md'):
        return md_path[:-len('index.md')] + 'index.html'
    return md_path[:-len('.md')] + '/index.html'


def read_page(md_path) -> str:
    """Read a page (resolving a snippet include), return '' if it does not exist."""
    try:
        with open(os.path.join(PAGES, md_path), encoding='utf-8') as f:
            text = f.read()
        m = re.match(r'--8<-- "(.+)"\s*$', text)
        if m:
            with open(os.path.join(PAGES, m.group(1)), encoding='utf-8') as f:
                text = f.read()
        return text
    except OSError:
        return ''


def clean(text) -> str:
    """Strip tags and entities from a heading and normalize whitespace."""
    text = text.replace('\\>', '\x00')  # escaped '>' is not the end of a tag
    text = html.unescape(re.sub(r'</?[a-zA-Z][^>]*>', '', text)).replace('\x00', '>')
    return re.sub(r'\s+', ' ', text).strip()


def strip_fences(text) -> str:
    """Remove fenced code blocks (their lines may start with '# ')."""
    return re.sub(r'^(```|~~~).*?^\1[^\n]*$', '', text, flags=re.M | re.S)


def get_h1(text):
    """Return the cleaned first H1 of a page or None."""
    body = strip_fences(text)
    m = re.search(r'^# (.+)$', body, flags=re.M)
    if m:
        return clean(m.group(1))
    m = re.search(r'<h1>(.*?)</h1>', body, flags=re.S)
    return clean(m.group(1)) if m else None


def split_top_level(text, seps=','):
    """Split at separators that are not nested in <>, () or []."""
    parts, depth, current = [], 0, ''
    for c in text:
        if c in '<([':
            depth += 1
        elif c in '>)]':
            depth -= 1
        if c in seps and depth <= 0:
            parts.append(current)
            current = ''
        else:
            current += c
    parts.append(current)
    return [p.strip() for p in parts if p.strip()]


OPERATOR_SYMBOLS = ('<=>', '<<', '>>', '<=', '>=', '<', '>')


def api_names(h1) -> list:
    """Derive the entry names from the H1 of an api page."""
    # hide the angle brackets of operators from the nesting detection
    for i, sym in enumerate(OPERATOR_SYMBOLS):
        h1 = h1.replace('operator' + sym, f'operator\x01{i}\x01')
    names = []
    for part in split_top_level(h1):
        name = part.replace('\\', '').replace('nlohmann::', '')
        name = re.sub(r'\x01(\d)\x01', lambda m: OPERATOR_SYMBOLS[int(m.group(1))], name)
        # drop qualifiers like "operator<<(basic_json)", but keep "operator()"
        if not name.endswith('operator()'):
            name = re.sub(r'(?<=\w|[<>=!+\-*/\[\]])\([^()]*\)$', '', name)
        if name not in names:
            names.append(name)
    return names


def first_cpp_block(text):
    """Return the first ```cpp block following the H1."""
    m = re.search(r'^# .*?^```cpp\n(.*?)^```', text, flags=re.M | re.S)
    return m.group(1) if m else None


def api_type(name, decl):
    """Determine the Dash entry type from name and declaration."""
    parts = name.split('::')
    last = parts[-1]
    if name.startswith('operator""'):
        return 'Literal'
    if last.startswith('operator'):
        return 'Operator'
    if decl is None:
        return None
    if re.search(r'\benum\b', decl):
        return 'Enum'
    if re.search(r'^\s*(template\s*<.*>\s*)?(class|struct)\s+\w+\s*(final\b|[:{;<]|$)', decl, flags=re.M):
        return 'Class'
    if re.search(r'\busing\s+\w+\s*=', decl) or 'typedef' in decl:
        return 'Type'
    if len(parts) > 1 and last == parts[-2]:
        return 'Constructor'
    if last.startswith('~'):
        return 'Method'
    if re.search(r'\bstatic\b', decl) or len(parts) == 1 or parts[0] == 'std':
        return 'Function'
    return 'Method'


def macro_names(h1) -> list:
    """Split the H1 of a macro page into macro names."""
    return [n.strip() for n in re.split(r'[,/]', h1) if n.strip()]


def api_entries(md_path):
    """Return the (name, type) pairs of an api page."""
    if md_path in OVERRIDES:
        return OVERRIDES[md_path]
    if md_path == 'api/macros/index.md':
        return [('Macros', 'Macro')]
    text = read_page(md_path)
    h1 = get_h1(text)
    if not h1:
        problem(md_path, 'no H1 found')
        return []
    if md_path.startswith('api/macros/'):
        return [(n, 'Macro') for n in macro_names(h1)]
    names = api_names(h1)
    if not names:
        problem(md_path, 'no names found')
        return []
    decl = first_cpp_block(text)
    result = []
    for name in names:
        kind = api_type(name, decl)
        if kind is None:
            problem(md_path, f'no type determinable for {name}')
        else:
            result.append((name, kind))
    return result


def guide_entries(nav):
    """Yield (name, type, md path) for all non-api nav pages."""
    for groups, title, md_path in walk_nav(nav):
        if md_path.startswith('api/') or md_path == 'index.md':
            continue
        if not md_path.endswith('.md'):
            continue
        groups = groups[1:]  # drop the top-level tab
        if title is None:
            title = get_h1(read_page(md_path))
            if not title:
                problem(md_path, 'no title found')
                continue
        # "Parsing: Parsing Untrusted Input" -> "Parsing: Untrusted Input"
        if groups and title.startswith(groups[-1] + ' ') and title[len(groups[-1]) + 1:][:1].isupper():
            title = title[len(groups[-1]) + 1:]
        if md_path.endswith('/index.md') and groups and title == groups[-1]:
            name = ': '.join(groups)
        else:
            name = ': '.join(groups + [title])
        yield name, 'Guide', md_path


def build_entries() -> list:
    """Return the sorted list of (name, type, path) index entries."""
    nav = load_mkdocs_yml()['nav']

    entries = set()
    for name, kind, md_path in guide_entries(nav):
        entries.add((name, kind, page_path(md_path)))

    api_root = os.path.join(PAGES, 'api')
    on_disk = set()
    for root, _, files in os.walk(api_root):
        for file in files:
            if file.endswith('.md'):
                rel = os.path.relpath(os.path.join(root, file), PAGES)
                on_disk.add(rel.replace(os.sep, '/'))
    for _, _, md_path in walk_nav(nav):
        if md_path.startswith('api/') and md_path not in on_disk:
            problem(md_path, 'listed in nav but missing on disk')
    for md_path in sorted(on_disk):
        for name, kind in api_entries(md_path):
            entries.add((name, kind, page_path(md_path)))
    return sorted(entries)


def write_index(entries, out) -> None:
    """Write the entries into a SQLite search index."""
    if os.path.exists(out):
        os.remove(out)
    con = sqlite3.connect(out)
    con.execute('CREATE TABLE searchIndex(id INTEGER PRIMARY KEY, name TEXT, type TEXT, path TEXT)')
    con.execute('CREATE UNIQUE INDEX anchor ON searchIndex (name, type, path)')
    con.executemany('INSERT INTO searchIndex(name, type, path) VALUES (?, ?, ?)', entries)
    con.commit()
    con.close()


def html_files(root):
    """Yield all HTML files below root."""
    for base, _, files in os.walk(root):
        for file in files:
            if file.endswith('.html'):
                yield os.path.join(base, file)


def read(path) -> str:
    with open(path, encoding='utf-8') as f:
        return f.read()


def write(path, text) -> None:
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


def remove_source_widget(docs) -> None:
    """Drop data-md-component=source so Material does not query api.github.com for the stars and version."""
    pattern = re.compile(r'\sdata-md-component=(?:"source"|source\b)')
    for path in html_files(docs):
        text = read(path)
        new = pattern.sub('', text)
        if new != text:
            write(path, new)


def patch_titles(docs, entries) -> None:
    """Strip the site name from all titles; use the index names where available."""
    names = {}
    for name, _, path in entries:
        names.setdefault(path, []).append(name)
    for file in html_files(docs):
        rel = os.path.relpath(file, docs).replace(os.sep, '/')
        text = read(file).replace(TITLE_SUFFIX, '</title>')
        if rel in names:
            title = html.escape(', '.join(names[rel]), quote=False)
            text = re.sub(r'<title>.*?</title>', lambda _: f'<title>{title}</title>', text, count=1, flags=re.S)
        write(file, text)


IMG_RE = re.compile(r'<img\b[^>]*>', re.I)
ATTR_RE = r'''(?:{0})\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))'''


def attr(tag, name):
    """Return the value of an attribute in a tag or None."""
    m = re.search(r'(?<![\w-])' + ATTR_RE.format(name), tag, flags=re.I)
    return next(g for g in m.groups() if g is not None) if m else None


def is_remote(url) -> bool:
    return re.match(r'(https?:)?//', url.strip(), flags=re.I) is not None


def download(url, docs) -> str:
    """Download url into assets/external and return the path relative to docs."""
    u = urllib.parse.urlparse(url if not url.startswith('//') else 'https:' + url)
    if u.scheme.lower() not in ('http', 'https'):
        raise ValueError(f'not an http(s) URL: {url}')
    req = urllib.request.Request(u.geturl(), headers={'User-Agent': USER_AGENT})
    # (the scheme is checked above)
    with urllib.request.urlopen(req, timeout=20) as r:  # nosec B310
        data = r.read()
        ctype = r.headers.get_content_type()
    path = urllib.parse.unquote(u.path).lstrip('/')
    ext = os.path.splitext(path)[1]
    if u.query or not ext or path.endswith('/'):
        digest = hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()[:12]
        path = os.path.join(os.path.dirname(path), digest + CONTENT_TYPE_EXT.get(ctype, ext or '.bin'))
    rel = os.path.normpath(os.path.join('assets', 'external', u.hostname, path))
    out = os.path.join(docs, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'wb') as f:
        f.write(data)
    return rel.replace(os.sep, '/')


def localize_images(docs) -> None:
    """Download remote images and rewrite their src; drop them on failure."""
    cache = {}
    for file in html_files(docs):
        text = read(file)

        def repl(m):
            tag = m.group(0)
            src = attr(tag, 'src')
            if src is None or not is_remote(src):
                return tag
            if src not in cache:
                try:
                    cache[src] = download(src, docs)
                except Exception as e:  # noqa: BLE001
                    print(f'generate_docset.py: warning: cannot download {src}: {e}', file=sys.stderr)
                    cache[src] = None
            if cache[src] is None:
                return attr(tag, 'alt') or ''
            local = os.path.relpath(os.path.join(docs, cache[src]), os.path.dirname(file))
            local = local.replace(os.sep, '/')
            return re.sub(ATTR_RE.format('src'), lambda _: f'src="{local}"', tag, count=1, flags=re.I)

        new = IMG_RE.sub(repl, text)
        if new != text:
            write(file, new)


def load_mkdocs_yml() -> dict:
    """Load mkdocs.yml, ignoring tags like !ENV and !!python/name."""
    with open(MKDOCS_YML, encoding='utf-8') as f:
        # (Loader is a yaml.SafeLoader)
        return yaml.load(f, Loader=Loader)  # nosec B506


def localize_site_urls(docs, site_url) -> None:
    """Load assets that the theme's JavaScript references by absolute site URL from the docset.

    The privacy plugin rewrites the mermaid loader to "<site_url>assets/external/unpkg.com/mermaid@11/...", so the
    docset would fetch mermaid from the live site. __md_scope is the site root that Material defines in every page.
    """
    pattern = re.compile(r'"' + re.escape(site_url) + r'(assets/[^"]*)"')
    for base, _, files in os.walk(docs):
        for file in (f for f in files if f.endswith('.js')):
            path = os.path.join(base, file)
            text = read(path)
            new = pattern.sub(r'new URL("\1",__md_scope).href', text)
            if new != text:
                write(path, new)


def remote_loads(docs, site_url) -> list:
    """Return 'file: url' strings for resources that would be loaded remotely."""
    found = []
    cdn = re.compile(r'https://(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|'
                     r'fonts\.googleapis\.com|fonts\.gstatic\.com)/[^\s"\'`)\\]*')
    css_url = re.compile(r'url\(\s*["\']?((?:https?:)?//[^)"\']+)', re.I)
    css_import = re.compile(r'@import\s+(?:url\(\s*)?["\']?((?:https?:)?//[^)"\'; ]+)', re.I)
    for base, _, files in os.walk(docs):
        for file in files:
            path = os.path.join(base, file)
            rel = os.path.relpath(path, docs)
            urls = []
            if file.endswith('.html'):
                text = read(path)
                for m in re.finditer(r'<[a-zA-Z][^>]*>', text):
                    tag = m.group(0)
                    for name in ('src', 'poster'):
                        v = attr(tag, name)
                        if v and is_remote(v):
                            urls.append(v)
                    v = attr(tag, 'srcset')
                    if v:
                        urls += [c.split()[0] for c in v.split(',') if c.strip() and is_remote(c.strip())]
                    if re.match(r'<link\b', tag, flags=re.I):
                        rel_attr = (attr(tag, 'rel') or '').lower()
                        v = attr(tag, 'href')
                        if v and is_remote(v) and re.search(r'stylesheet|icon|preload|modulepreload|manifest', rel_attr):
                            urls.append(v)
                urls += css_url.findall(text) + css_import.findall(text)
            elif file.endswith('.css'):
                text = read(path)
                urls += css_url.findall(text) + css_import.findall(text)
            elif file.endswith('.js'):
                text = read(path)
                urls += cdn.findall(text)
                urls += re.findall(re.escape(site_url) + r'assets/[^\s"\'`)\\]*', text)
            found += [f'{rel}: {u}' for u in urls if u not in ALLOWED_REMOTE]
    return found


def make_docset(site, out_dir) -> int:
    entries = build_entries()
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1
    docset = os.path.join(out_dir, DOCSET)
    docs = os.path.join(docset, 'Contents', 'Resources', 'Documents')
    if os.path.exists(docset):
        shutil.rmtree(docset)
    shutil.copytree(site, docs)
    for icon in ('icon.png', 'icon@2x.png'):
        shutil.copy(os.path.join(HERE, icon), docset)
    shutil.copy(os.path.join(HERE, 'Info.plist'), os.path.join(docset, 'Contents'))
    write_index(entries, os.path.join(docset, 'Contents', 'Resources', 'docSet.dsidx'))

    # patch CSS to hide navigation items and fix spacing
    css = glob.glob(os.path.join(docs, 'assets', 'stylesheets', 'main.*.min.css'))
    if len(css) != 1:
        print(f'generate_docset.py: expected exactly one main.*.min.css, found {len(css)}', file=sys.stderr)
        return 1
    with open(css[0], 'a', encoding='utf-8') as f:
        f.write(CSS_PATCH)

    patch_titles(docs, entries)
    remove_source_widget(docs)
    for sitemap in glob.glob(os.path.join(docs, 'sitemap.*')):
        os.remove(sitemap)

    # make the docset self-contained
    site_url = load_mkdocs_yml()['site_url']
    localize_images(docs)
    localize_site_urls(docs, site_url)
    remote = remote_loads(docs, site_url)
    if remote:
        print('generate_docset.py: remote resources remain in the docset:', file=sys.stderr)
        print('\n'.join('  ' + r for r in remote), file=sys.stderr)
        return 1
    return 0


def make_tgz(out_dir) -> int:
    docset = os.path.join(out_dir, DOCSET)
    if not os.path.isdir(docset):
        print(f'generate_docset.py: {docset} does not exist', file=sys.stderr)
        return 1
    with tarfile.open(os.path.join(out_dir, 'JSON_for_Modern_C++.tgz'), 'w:gz') as tar:
        tar.add(docset, arcname=DOCSET, filter=lambda i: None if os.path.basename(i.name) == '.DS_Store' else i)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='print the index entries as TSV')
    p = sub.add_parser('index', help='write the SQLite search index')
    p.add_argument('out')
    p = sub.add_parser('docset', help='build the docset from a built mkdocs site')
    p.add_argument('site_dir')
    p.add_argument('out_dir')
    p = sub.add_parser('tgz', help='pack the docset into a tarball')
    p.add_argument('out_dir')
    args = parser.parse_args()

    if args.command == 'docset':
        return make_docset(args.site_dir, args.out_dir)
    if args.command == 'tgz':
        return make_tgz(args.out_dir)

    entries = build_entries()
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1
    if args.command == 'list':
        for entry in entries:
            print('\t'.join(entry))
    elif args.command == 'index':
        write_index(entries, args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
