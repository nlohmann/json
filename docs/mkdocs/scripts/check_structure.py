#!/usr/bin/env python

import glob
import os.path
import re

warnings = 0


def report(rule, location, description):
    global warnings
    warnings += 1
    print(f'{warnings:3}. {location}:  {description} [{rule}]')


def check_structure():
    expected_sections = [
        'Template parameters',
        'Specializations',
        'Iterator invalidation',
        'Requirements',
        'Member types',
        'Member functions',
        'Member variables',
        'Static functions',
        'Non-member functions',
        'Literals',
        'Helper classes',
        'Parameters',
        'Return value',
        'Exception safety',
        'Exceptions',
        'Complexity',
        'Possible implementation',
        'Default definition',
        'Notes',
        'Examples',
        'See also',
        'Version history'
    ]

    required_sections = [
        'Examples',
        'Version history'
    ]

    files = sorted(glob.glob('api/**/*.md', recursive=True))
    for file in files:
        with open(file) as file_content:
            section_idx = -1
            existing_sections = []
            in_initial_code_example = False
            previous_line = None
            h1sections = 0

            for lineno, line in enumerate(file_content.readlines()):
                line = line.strip()

                if line.startswith('# '):
                    h1sections += 1

                # there should only be one top-level title
                if h1sections > 1:
                    report('structure/unexpected_section', f'{file}:{lineno+1}', f'unexpected top-level title "{line}"')
                    h1sections = 1

                # Overview pages should have a better title
                if line == '# Overview':
                    report('style/title', f'{file}:{lineno+1}', 'overview pages should have a better title than "Overview"')

                # lines longer than 160 characters are bad (unless they are tables)
                if len(line) > 160 and '|' not in line:
                    report('whitespace/line_length', f'{file}:{lineno+1}', f'line is too long ({len(line)} vs. 160 chars)')

                # check if sections are correct
                if line.startswith('## '):
                    current_section = line.strip('## ')
                    existing_sections.append(current_section)

                    if current_section in expected_sections:
                        idx = expected_sections.index(current_section)
                        if idx <= section_idx:
                            report('structure/section_order', f'{file}:{lineno+1}', f'section "{current_section}" is in an unexpected order (should be before "{expected_sections[section_idx]}")')
                        section_idx = idx
                    else:
                        report('structure/unknown_section', f'{file}:{lineno+1}', f'section "{current_section}" is not part of the expected sections')

                # code example
                if line == '```cpp' and section_idx == -1:
                    in_initial_code_example = True

                if in_initial_code_example and line.startswith('//'):
                    if any(map(str.isdigit, line)) and '(' not in line:
                        report('style/numbering', f'{file}:{lineno+1}', 'number should be in parentheses: {line}')

                if line == '```' and in_initial_code_example:
                    in_initial_code_example = False

                # consecutive blank lines are bad
                if line == '' and previous_line == '':
                    report('whitespace/blank_lines', f'{file}:{lineno}-{lineno+1}', 'consecutive blank lines')

                # check that non-example admonitions have titles
                untitled_admonition = re.match(r'^(\?\?\?|!!!) ([^ ]+)$', line)
                if untitled_admonition and untitled_admonition.group(2) != 'example':
                    report('style/admonition_title', f'{file}:{lineno}', f'"{untitled_admonition.group(2)}" admonitions should have a title')

                previous_line = line

            for required_section in required_sections:
                if required_section not in existing_sections:
                    report('structure/missing_section', f'{file}:{lineno+1}', f'required section "{required_section}" was not found')


def check_examples():
    example_files = sorted(glob.glob('../../examples/*.cpp'))
    markdown_files = sorted(glob.glob('**/*.md', recursive=True))

    # check if every example file is used in at least one markdown file
    for example_file in example_files:
        example_file = os.path.join('examples', os.path.basename(example_file))

        found = False
        for markdown_file in markdown_files:
            content = ' '.join(open(markdown_file).readlines())
            if example_file in content:
                found = True
                break

        if not found:
            report('examples/missing', f'{example_file}', 'example file is not used in any documentation file')


if __name__ == '__main__':
    print(120 * '-')
    check_structure()
    check_examples()
    print(120 * '-')
