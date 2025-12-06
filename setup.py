import setuptools
import subprocess
from os import path


name = 'noAPIframe'


version = None
try:
    version = subprocess.check_output('git describe', shell=True).decode('UTF-8').strip()
    version = version.strip().replace('v', '', 1).rsplit('-', 1)[0].replace('-', '.')
except Exception:
    version = '0.0.0'


def read_text(file_name):
    with open(path.join(path.abspath(path.dirname(__file__)), file_name)) as f:
        return f.read()


params = dict(
    name=name,
    version=version,
    description='Basic framework for creating REST backends and just focus on businesslogic',
    long_description=read_text('README.md'),
    long_description_content_type='text/markdown',
    author='Nils Ost',
    author_email='home@nijos.de',
    license=read_text('LICENSE'),
    packages=[
        'noapiframe',
    ],
    install_requires=[
        'CherryPy>=18.6.0',
        'cherrypy-cors>=1.6.0',
        'pycryptodome>=3.23.0',
        'pymongo>=4.11.1'
    ],
    python_requires='>=3.8',
)


__name__ == '__main__' and setuptools.setup(**params)
