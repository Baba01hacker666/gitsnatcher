from setuptools import setup, find_packages
import os

readme_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), "README.md")
long_description = open(readme_path, encoding="utf-8").read() if os.path.exists(readme_path) else ""

setup(
    name="gitsnatcher",
    version="2.0.0",
    author="baba01hacker",
    description="Professional .git repository reconstructor, source extractor, and intelligence analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Baba01hacker666/gitsnatcher",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "gitsnatcher=gitsnatcher.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Version Control :: Git",
        "Topic :: Utilities",
    ],
    python_requires='>=3.7',
)
