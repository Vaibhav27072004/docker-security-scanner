"""
Docker Security Scanner — Python Package Setup
===============================================
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip()
        for line in fh
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="docker-security-scanner",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description=(
        "Automated Docker Image Security Scanner — "
        "CVE detection, secret scanning, Dockerfile linting, and SBOM generation"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/docker-security-scanner",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/docker-security-scanner/issues",
        "Documentation": "https://github.com/yourusername/docker-security-scanner/docs",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(exclude=["tests*", "examples*"]),
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "docker-scan=src.scanner:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
