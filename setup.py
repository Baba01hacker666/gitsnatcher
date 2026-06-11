from setuptools import setup, find_packages

setup(
    name="gitsnatcher",
    version="1.0.0",
    author="Baba01hacker666",
    description="Professional .git repository reconstructor and extractor",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/baba01hacker/gitsnatcher",
    packages=find_packages(),
    install_requires=[
        "requests",
        "urllib3",
    ],
    entry_points={
        "console_scripts": [
            "gitsnatcher=gitsnatcher.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
