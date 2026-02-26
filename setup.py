from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip()]

setup(
    name="mini-security-scanner",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Web Güvenlik Tarama Aracı - Termux & Windows Uyumlu",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zaza219-hub/mini-security-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "scanner=scanner:main",
        ]
    },
)