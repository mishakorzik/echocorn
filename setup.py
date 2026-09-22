import os
import re

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(HERE, "README.md"), encoding="utf-8") as fh:
    long_description = fh.read()

with open(os.path.join(HERE, "echocorn", "utils.py"), encoding="utf-8") as fh:
    match = re.search(r'^VERSION = "([^"]+)"', fh.read(), re.MULTILINE)
    if match is None:
        raise RuntimeError("Unable to determine the package version")
    version = match.group(1)

setup(
    name="echocorn",
    version=version,
    license="Apache 2.0",
    packages=find_packages(exclude=("tests", "tests.*")),
    description="Fast asyncio ASGI server with HTTP/1.1 and HTTP/2 support",
    # tomllib, the TOML reader used for the configuration file, is in the
    # standard library from 3.11 on.
    python_requires=">=3.11",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MishaKorzhik_He1Zen",
    author_email="developer.mishakorzhik@gmail.com",
    url="https://github.com/mishakorzik/echocorn",
    project_urls={
        "Bug Tracker": "https://github.com/mishakorzik/echocorn/issues",
        "Donate": "https://www.buymeacoffee.com/misakorzik",
    },
    install_requires=[
        "h2>=4.1.0",
    ],
    extras_require={
        "uvloop": ["uvloop>=0.17; platform_system != 'Windows'"],
        "test": [
            "pytest>=7",
            "httpx>=0.24",
            "starlette>=0.27",
            "quart>=0.19",
            "flask>=3",
            "asgiref>=3.6",
            "websockets>=12",
            "cryptography>=41",
        ],
    },
    keywords=[
        "asgi",
        "async",
        "asyncio",
        "uvloop",
        "websocket",
        "websockets",
        "wsgi",
        "fast",
        "http",
        "http2",
        "h11",
        "h2",
        "https",
        "hsts",
        "tls",
        "server",
        "secure",
        "dualstack",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.15",
        "Programming Language :: Python :: 3.16",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Framework :: AsyncIO",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Environment :: Web Environment",
    ],
    entry_points={
        "console_scripts": [
            "echocorn = echocorn.__main__:main",
        ],
    },
)
