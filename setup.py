from setuptools import setup
import re
import subprocess

try:
    long_description = subprocess.check_output(
        'pandoc --to rst README.md', shell=True).decode()
except(IOError, ImportError, subprocess.CalledProcessError):
    long_description = open('README.md').read()

with open('deploygraph/__init__.py', 'r') as fd:
    version = re.search(
        r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(),
        re.MULTILINE).group(1)


download_url = 'https://github.com/jvinyard/deploygraph/tarball/{version}' \
    .format(**locals())


with open('requirements.txt', 'r') as f:
    requirements = f.read().split('\n')

setup(
    name='deploygraph',
    version=version,
    url='https://github.com/JohnVinyard/deploygraph',
    author='John Vinyard',
    author_email='john.vinyard@gmail.com',
    long_description=long_description,
    download_url=download_url,
    packages=[
        'deploygraph',
    ],
    install_requires=requirements,
)
