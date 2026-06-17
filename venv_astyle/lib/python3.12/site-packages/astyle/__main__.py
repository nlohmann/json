r"""This module can be called by
`python -m <https://docs.python.org/3/library/__main__.html>`_.
"""

import os
import subprocess
import sys
import sysconfig
from typing import Any

from . import __name__ as NAME


def main(*args: Any) -> int:
    r"""Run main program.

    :param args:
    :type args: Any
    :rtype: int
    """
    paths = [
        os.path.join(
            sysconfig.get_path("scripts", scheme),
            NAME + sysconfig.get_config_var("EXE"),
        )
        for scheme in [
            sysconfig.get_preferred_scheme("user"),
            sysconfig.get_default_scheme(),
        ]
    ]
    for path in paths:
        if os.path.isfile(path):
            break
    else:
        raise FileNotFoundError(paths)
    return subprocess.run((path,) + args).returncode


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
