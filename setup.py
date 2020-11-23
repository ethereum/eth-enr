#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import (
    setup,
    find_packages,
)

extras_require = {
    'test': [
        "factory-boy==3.0.1",
        "pytest==6.0.1",
        "pytest-xdist==2.1.0",
        "tox==3.19.0",
    ],
    'lint': [
        "flake8==3.8.3",
        "isort==5.4.2",
        "mypy==0.782",
        "pydocstyle>=3.0.0,<4",
        "black==20.8b1",
    ],
    'doc': [
        "Sphinx>=1.6.5,<2",
        "sphinx_rtd_theme>=0.1.9",
        "towncrier>=19.2.0, <20",
    ],
    'dev': [
        "bumpversion>=0.5.3,<1",
        "pytest-watch>=4.1.0,<5",
        "wheel",
        "twine",
        "ipython",
    ],
}

extras_require['dev'] = (
    extras_require['dev'] +  # noqa: W504
    extras_require['test'] +  # noqa: W504
    extras_require['lint'] +  # noqa: W504
    extras_require['doc']
)


with open('./README.md') as readme:
    long_description = readme.read()


setup(
    name='eth-enr',
    # *IMPORTANT*: Don't manually change the version here. Use `make bump`, as described in readme
    version='0.4.0',
    description="""eth-enr: Python library for ENR (EIP-778) records""",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='The Ethereum Foundation',
    author_email='snakecharmers@ethereum.org',
    url='https://github.com/ethereum/eth-enr',
    include_package_data=True,
    install_requires=[
        "eth-hash[pycryptodome]>=0.1.4,<1",
        "eth-keys>=0.3.3,<0.4.0",
        "eth-utils>=1,<2",
        "eth-typing>=2.2.2,<3",
        "rlp>=2.0.0a1,<3.0.0",
    ],
    python_requires='>=3.6, <4',
    extras_require=extras_require,
    py_modules=['eth_enr'],
    license="MIT",
    zip_safe=False,
    keywords='ethereum',
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={'eth_enr': ['py.typed']},
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
