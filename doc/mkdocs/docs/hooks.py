import shutil
import os.path


def copy_doxygen(*args, **kwargs):
    doxygen_dir = os.path.join(kwargs['config']['site_dir'], 'doxygen')
    if not os.path.isdir(doxygen_dir) or not os.listdir(doxygen_dir):
        print('Copy Doxygen files...')
        shutil.copytree('../html', doxygen_dir)
        print('Copy Doxygen complete')
