#!/usr/bin/env python

import glob


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
        'Version history'
    ]

    for file in glob.glob('api/**/*.md', recursive=True):
        with open(file) as file_content:
            header_idx = -1
            existing_headers = []
            in_initial_code_example = False

            for lineno, line in enumerate(file_content.readlines()):
                line = line.strip()

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

            for required_header in required_headers:
                if required_header not in existing_headers:
                    print(f'{file}:{lineno+1}: Error: required header "{required_header}" was not found!')


if __name__ == '__main__':
    check_structure()
