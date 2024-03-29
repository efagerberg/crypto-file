import sys
from setuptools import setup, find_packages

setup(
    name='crypto-file',
    version='1.0.1',
    description='Read encrypted files',
    long_description=open('README.rst').read(),
    author='Jordan Nickerson, Evan Fagerberg',
    author_email='adioevan@gmail.com',
    zip_safe=True,
    url='http://github.com/efagerberg/crypto-file',
    packages=find_packages(exclude=('tests',)),
    keywords='encryption filehandling',
    install_requires=['pycryptodome>=3.6.6'],
    setup_requires=['pytest-runner']
        if any(x in ('pytest', 'test') for x in sys.argv) else [],
    tests_require=['mock', 'pytest', 'pytest-cov', 'pytest-xdist'],
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
        "Programming Language :: Python :: 2.7",
        "Topic :: Encryption",
    ])
