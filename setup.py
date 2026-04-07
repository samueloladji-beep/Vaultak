from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vaultak",
    version="0.5.0",
    author="Samuel Oladji",
    author_email="samueloladji@gmail.com",
    description="Real-time behavioral kill switch for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/samueloladji-beep/Agentbreaker-",
    packages=find_packages(),
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
