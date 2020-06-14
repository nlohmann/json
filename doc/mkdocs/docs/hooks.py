import shutil
import os.path


def copy_doxygen(*args, **kwargs):
    shutil.copytree('../html', os.path.join(kwargs['config']['site_dir'], 'doxygen'))
    print('Copy Doxygen complete')
