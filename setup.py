from setuptools import setup, find_packages
import sys, os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="echocorn",
    version="1.0.0b",
    license="Apache 2.0",
    packages=find_packages(),
    description="Very fast asynchronous asgi server with HTTP/1.1 and HTTP/2.0",
    python_requires=">=3.7",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MishaKorzhik_He1Zen",
    author_email="developer.mishakorzhik@gmail.com",
    url="https://github.com/mishakorzik/echocorn",
    project_urls={
        "Bug Tracker": "https://github.com/mishakorzik/echocorn/issues",
        "Donate": "https://www.buymeacoffee.com/misakorzik"
    },
    install_requires=[
        "h2>=4.0.0"
    ],
    keywords=[
        "asgi",
        "async",
        "uvloop",
        "fast",
        "http",
        "https",
        "hsts",
        "tls",
        "server",
        "secure",
        "secured",
        "dualstack"
    ],
    classifiers = [
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Framework :: AsyncIO",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Environment :: Web Environment"
    ],
    entry_points={
        "console_scripts": [
            "echocorn = echocorn.__main__:main",
        ],
    },
)
