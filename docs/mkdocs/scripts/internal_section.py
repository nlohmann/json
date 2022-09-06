import sys

from copy import deepcopy
from mkdocs.structure.nav import Navigation, Section, Page

def _get_internal_sections(items, current_page):
    res = []
    sections = [item for item in items if isinstance(item, Section)]
    while sections:
        for section in sections[:]:
            for item in section.children:
                if isinstance(item, Section):
                    sections.append(item)
                elif isinstance(item, Page):
                    if item.meta.get("x-nlohmann-json-is-internal", False):
                        res.append(section)
            sections.remove(section)
    return res

def on_page_context(context, page, config, nav):
    sys.setrecursionlimit(1200)
    nav = deepcopy(nav)
    context["nav"] = nav

    sections = _get_internal_sections(nav.items, page)
    for section in sections:
        if not section.active:
            section.children = [child for child in section.children if child.is_index]

    return context
