#!/usr/bin/env python

import glob
import os.path
import re
import sys

import yaml

warnings = 0


def report(rule, location, description) -> None:
    global warnings
    warnings += 1
    print(f'{warnings:3}. {location}:  {description} [{rule}]')


def check_structure() -> None:
    expected_sections = [
        "Template parameters",
        "Specializations",
        "Iterator invalidation",
        "Requirements",
        "Member types",
        "Member functions",
        "Member variables",
        "Static functions",
        "Non-member functions",
        "Literals",
        "Helper classes",
        "Parameters",
        "Return value",
        "Exception safety",
        "Exceptions",
        "Complexity",
        "Possible implementation",
        "Default definition",
        "Notes",
        "Examples",
        "See also",
        "Version history",
    ]

    required_sections = [
        "Examples",
        "Version history",
    ]

    files = sorted(glob.glob("api/**/*.md", recursive=True))
    for file in files:
        with open(file) as file_content:
            section_idx = -1                 # the index of the current h2 section
            existing_sections = []           # the list of h2 sections in the file
            in_initial_code_example = False  # whether we are inside the first code example block
            previous_line = None             # the previous read line
            h1sections = 0                   # the number of h1 sections in the file
            last_overload = 0                # the last seen overload number in the code example
            documented_overloads = {}        # the overloads that have been documented in the current block
            current_section = None           # the name of the current section

            for lineno, original_line in enumerate(file_content.readlines()):
                line = original_line.strip()

                if line.startswith("# "):
                    h1sections += 1

                # there should only be one top-level title
                if h1sections > 1:
                    report("structure/unexpected_section", f"{file}:{lineno+1}", f'unexpected top-level title "{line}"')
                    h1sections = 1

                # Overview pages should have a better title
                if line == "# Overview":
                    report("style/title", f"{file}:{lineno+1}", 'overview pages should have a better title than "Overview"')

                # lines longer than 160 characters are bad (unless they are tables)
                if len(line) > 160 and "|" not in line:
                    report("whitespace/line_length", f"{file}:{lineno+1} ({current_section})", f"line is too long ({len(line)} vs. 160 chars)")

                # sections in `<!-- NOLINT -->` comments are treated as present
                if line.startswith("<!-- NOLINT"):
                    current_section = line.strip("<!-- NOLINT")
                    current_section = current_section.strip(" -->")
                    existing_sections.append(current_section)

                # check if sections are correct
                if line.startswith("## "):
                    # before starting a new section, check if the previous one documented all overloads
                    if current_section in documented_overloads and last_overload != 0:
                        if len(documented_overloads[current_section]) > 0 and len(documented_overloads[current_section]) != last_overload:
                            expected = list(range(1, last_overload+1))
                            undocumented = [x for x in expected if x not in documented_overloads[current_section]]
                            unexpected = [x for x in documented_overloads[current_section] if x not in expected]
                            if len(undocumented):
                                report("style/numbering", f"{file}:{lineno} ({current_section})", f'undocumented overloads: {", ".join([f"({x})" for x in undocumented])}')
                            if len(unexpected):
                                report("style/numbering", f"{file}:{lineno} ({current_section})", f'unexpected overloads: {", ".join([f"({x})" for x in unexpected])}')

                    current_section = line.strip("## ")
                    existing_sections.append(current_section)

                    if current_section in expected_sections:
                        idx = expected_sections.index(current_section)
                        if idx <= section_idx:
                            report("structure/section_order", f"{file}:{lineno+1}", f'section "{current_section}" is in an unexpected order (should be before "{expected_sections[section_idx]}")')
                        section_idx = idx
                    elif "index.md" not in file:  # index.md files may have a different structure
                        report("structure/unknown_section", f"{file}:{lineno+1}", f'section "{current_section}" is not part of the expected sections')

                # collect the numbered items of the current section to later check if they match the number of overloads
                if last_overload != 0 and not in_initial_code_example:
                    if len(original_line) and original_line[0].isdigit():
                        number = int(re.findall(r"^(\d+).", original_line)[0])
                        if current_section not in documented_overloads:
                            documented_overloads[current_section] = []
                        documented_overloads[current_section].append(number)

                # code example
                if line == "```cpp" and section_idx == -1:
                    in_initial_code_example = True

                if in_initial_code_example and line.startswith("//") and line not in ["// since C++20", "// until C++20"]:
                    # check numbering of overloads
                    if any(map(str.isdigit, line)):
                        number = int(re.findall(r"\d+", line)[0])
                        if number != last_overload + 1:
                            report("style/numbering", f"{file}:{lineno+1}", f"expected number ({number}) to be ({last_overload +1 })")
                        last_overload = number

                    if any(map(str.isdigit, line)) and "(" not in line:
                        report("style/numbering", f"{file}:{lineno+1}", f"number should be in parentheses: {line}")

                if line == "```" and in_initial_code_example:
                    in_initial_code_example = False

                # consecutive blank lines are bad
                if line == "" and previous_line == "":
                    report("whitespace/blank_lines", f"{file}:{lineno}-{lineno+1} ({current_section})", "consecutive blank lines")

                # check that non-example admonitions have titles
                untitled_admonition = re.match(r"^(\?\?\?|!!!) ([^ ]+)$", line)
                if untitled_admonition and untitled_admonition.group(2) != "example":
                    report("style/admonition_title", f"{file}:{lineno} ({current_section})", f'"{untitled_admonition.group(2)}" admonitions should have a title')

                previous_line = line

            if "index.md" not in file:  # index.md files may have a different structure
                for required_section in required_sections:
                    if required_section not in existing_sections:
                        report("structure/missing_section", f"{file}:{lineno+1}", f'required section "{required_section}" was not found')


def check_examples() -> None:
    example_files = sorted(glob.glob("../../examples/*.cpp"))
    markdown_files = sorted(glob.glob("**/*.md", recursive=True))

    # check if every example file is used in at least one markdown file
    for example_file in example_files:
        example_file = os.path.join("examples", os.path.basename(example_file))

        found = False
        for markdown_file in markdown_files:
            content = " ".join(open(markdown_file).readlines())
            if example_file in content:
                found = True
                break

        if not found:
            report("examples/missing", f"{example_file}", "example file is not used in any documentation file")


def check_links() -> None:
    """Check that every entry in the navigation (nav in mkdocs.yml) links to at most one file. If a file is linked more
    than once, then the first entry is repeated. See https://github.com/nlohmann/json/issues/4564 for the issue in
    this project and https://github.com/mkdocs/mkdocs/issues/3428 for the root cause.

    The issue can be fixed by merging the keys, so

    - 'NLOHMANN_JSON_VERSION_MAJOR': api/macros/nlohmann_json_version_major.md
    - 'NLOHMANN_JSON_VERSION_MINOR': api/macros/nlohmann_json_version_major.md

    would be replaced with

    - 'NLOHMANN_JSON_VERSION_MAJOR, NLOHMANN_JSON_VERSION_MINOR': api/macros/nlohmann_json_version_major.md
    """
    file_with_path = {}

    def collect_links(node, path="") -> None:
        if isinstance(node, list):
            for x in node:
                collect_links(x, path)
        elif isinstance(node, dict):
            for p, x in node.items():
                collect_links(x, path + "/" + p)
        else:
            if node not in file_with_path:
                file_with_path[node] = []
            file_with_path[node].append(path)

    with open("../mkdocs.yml") as mkdocs_file:
        # see https://github.com/yaml/pyyaml/issues/86#issuecomment-1042485535
        yaml.add_multi_constructor("tag:yaml.org,2002:python/name", lambda loader, suffix, node: None, Loader=yaml.SafeLoader)
        yaml.add_multi_constructor("!ENV", lambda loader, suffix, node: None, Loader=yaml.SafeLoader)
        y = yaml.safe_load(mkdocs_file)

        collect_links(y["nav"])
        for duplicate_file in [x for x in file_with_path if len(file_with_path[x]) > 1]:
            file_list = [f'"{x}"' for x in file_with_path[duplicate_file]]
            file_list_str = ", ".join(file_list)
            report("nav/duplicate_files", "mkdocs.yml", f'file "{duplicate_file}" is linked with multiple keys in "nav": {file_list_str}; only one is rendered properly, see #4564')


if __name__ == "__main__":
    print(120 * "-")
    check_structure()
    check_examples()
    check_links()
    print(120 * "-")

    if warnings > 0:
        sys.exit(1)
