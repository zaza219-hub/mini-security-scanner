from setuptools import setup, find_packages

setup(
    name="websecscanner",
    version="1.0.0",
    description="Web Güvenlik Tarama Aracı",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://github.com/yourusername/websecscanner",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "colorama>=0.4.6",
        "lxml>=4.9.0"
    ],
    entry_points={
        "console_scripts": [
            "websecscanner=scanner:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)