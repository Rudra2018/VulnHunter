"""
Setup script for VulnHunter V5
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "VulnHunter V5 - Advanced Hybrid Static-Dynamic Vulnerability Detection"

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="vulnhunter-v5",
    version="5.0.0",
    author="VulnHunter Research Team",
    author_email="research@vulnhunter.ai",
    description="Advanced Hybrid Static-Dynamic Vulnerability Detection for Smart Contracts and Source Code",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Rudra2018/VulnHunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
        ],
        "docs": [
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
            "myst-parser>=2.0.0",
        ],
        "fuzzing": [
            "atheris>=2.3.0",
            "pyfuzz>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vulnhunter=src.deploy.cli:cli",
            "vulnhunter-api=src.deploy.api:main",
        ],
    },
    package_data={
        "src": [
            "data/cache/.gitkeep",
            "models/.gitkeep",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "vulnerability detection",
        "static analysis",
        "dynamic analysis",
        "smart contracts",
        "machine learning",
        "security",
        "fuzzing",
        "graph neural networks",
        "transformers",
    ],
    project_urls={
        "Bug Reports": "https://github.com/Rudra2018/VulnHunter/issues",
        "Source": "https://github.com/Rudra2018/VulnHunter",
        "Documentation": "https://vulnhunter.readthedocs.io/",
    },
)