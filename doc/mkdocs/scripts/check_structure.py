#!/usr/bin/env python

import glob
import os.path


def check_structure():
    expected_headers = [
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
        'Notes',
        'Examples',
        'See also',
        'Version history'
    ]

    required_headers = [
        'Examples',
        'Version history'
    ]

    files = sorted(glob.glob('api/**/*.md', recursive=True))
    for file in files:
        with open(file) as file_content:
            header_idx = -1
            existing_headers = []
            in_initial_code_example = False
            previous_line = None
            h1sections = 0

            for lineno, line in enumerate(file_content.readlines()):
                line = line.strip()

                if line.startswith('# '):
                    h1sections += 1

                # there should only be one top-level title
                if h1sections > 1:
                    print(f'{file}:{lineno+1}: Error: unexpected top-level title "{line}"!')
                    h1sections = 1

                # Overview pages should have a better title
                if line == '# Overview':
                    print(f'{file}:{lineno+1}: Error: overview pages should have a better title!')

                # lines longer than 160 characters are bad (unless they are tables)
                if len(line) > 160 and '|' not in line:
                    print(f'{file}:{lineno+1}: Error: line is too long ({len(line)} vs. 160 chars)!')

                # check if headers are correct
                if line.startswith('## '):
                    header = line.strip('## ')
                    existing_headers.append(header)

                    if header in expected_headers:
                        idx = expected_headers.index(header)
                        if idx <= header_idx:
                            print(f'{file}:{lineno+1}: Error: header "{header}" is in an unexpected order (should be before "{expected_headers[header_idx]}")!')
                        header_idx = idx
                    else:
                        print(f'{file}:{lineno+1}: Error: header "{header}" is not part of the expected headers!')

                # code example
                if line == '```cpp' and header_idx == -1:
                    in_initial_code_example = True

                if in_initial_code_example and line.startswith('//'):
                    if any(map(str.isdigit, line)) and '(' not in line:
                        print(f'{file}:{lineno+1}: Number should be in parentheses: {line}')

                if line == '```' and in_initial_code_example:
                    in_initial_code_example = False

                # consecutive blank lines are bad
                if line == '' and previous_line == '':
                    print(f'{file}:{lineno}-{lineno+1}: Error: Consecutive blank lines!')

                previous_line = line

            for required_header in required_headers:
                if required_header not in existing_headers:
                    print(f'{file}:{lineno+1}: Error: required header "{required_header}" was not found!')


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
            print(f'{example_file}: Error: example file is not used in any documentation file!')


if __name__ == '__main__':
    check_structure()
    check_examples()
