#!/usr/bin/env python

import glob


def check_structure():
    expected_headers = [
        'Specializations',
        'Template parameters',
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

            for lineno, line in enumerate(file_content.readlines()):
                line = line.strip()

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

            for required_header in required_headers:
                if required_header not in existing_headers:
                    print(f'{file}:{lineno+1}: Error: required header "{required_header}" was not found!')


if __name__ == '__main__':
    check_structure()
