// Check that every Mermaid diagram in the documentation parses.
//
// MkDocs does not validate Mermaid diagrams; a syntax error only shows up as an error box in the browser. This script
// extracts every ```mermaid block from the Markdown files and runs it through mermaid.parse(), the same parser the
// site uses (Material for MkDocs loads mermaid@11). Mermaid needs a DOM (DOMPurify), so jsdom provides one; the globals
// must be set before Mermaid is imported, hence the dynamic import.
//
// usage: node check_mermaid.mjs <docs directory>

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { JSDOM } from 'jsdom';

const { window } = new JSDOM('<!DOCTYPE html><html><body></body></html>', { pretendToBeVisual: true });
globalThis.window = window;
globalThis.document = window.document;
globalThis.DOMParser = window.DOMParser;
const { default: mermaid } = await import('mermaid');
mermaid.initialize({ startOnLoad: false });

const docsDir = process.argv[2] ?? 'docs';
const opening = /^(\s*)(`{3,}|~{3,})\s*mermaid\s*$/;
let diagrams = 0;
let errors = 0;

for (const file of readdirSync(docsDir, { recursive: true }).filter((f) => f.endsWith('.md')).sort()) {
    const lines = readFileSync(join(docsDir, file), 'utf8').split('\n');
    for (let i = 0; i < lines.length; ++i) {
        const match = opening.exec(lines[i]);
        if (!match) {
            continue;
        }
        // strip the indentation of the opening fence from every line (blocks inside admonitions or lists), like
        // pymdownx.superfences does
        const [, indent, fence] = match;
        const closing = new RegExp(`^\\s*\\${fence[0]}{${fence.length},}\\s*$`);
        const body = [];
        let j = i + 1;
        for (; j < lines.length && !closing.test(lines[j]); ++j) {
            body.push(lines[j].startsWith(indent) ? lines[j].slice(indent.length) : lines[j].trimStart());
        }
        ++diagrams;
        try {
            await mermaid.parse(body.join('\n'));
        } catch (error) {
            ++errors;
            console.log(`${join(docsDir, file)}:${i + 1}: ${String(error?.message ?? error).replaceAll('\n', '\n    ')}`);
        }
        i = j;
    }
}

console.log(`checked ${diagrams} Mermaid diagrams, ${errors} invalid`);
process.exitCode = errors ? 1 : 0;
