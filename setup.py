"""
Secret Sharing
==============

"""

from setuptools import setup
from secretsharing import __version__

setup(
    name='secretsharing',
    version=__version__,
    url='https://github.com/onenameio/secret-sharing',
    license='MIT',
    author='Halfmoon Labs',
    author_email='hello@halfmoon.io',
    description=("Tools for sharing secrets (like Bitcoin private keys), "
                 "using shamir's secret sharing scheme."),
    packages=[
        'secretsharing',
    ],
    zip_safe=False,
    install_requires=[
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)
