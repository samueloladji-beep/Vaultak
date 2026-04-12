from setuptools import setup, find_packages

setup(
    name="vaultak-sentry",
    version="0.6.1",
    description="Vaultak Sentry — monitor any AI agent with zero code changes",
    long_description="Monitor any AI agent process with zero code changes. Automatic behavioral monitoring, risk scoring, and alerts.",
    author="Vaultak",
    url="https://vaultak.com",
    packages=find_packages(),
    py_modules=["vaultak_sentry_runner"],
    entry_points={
        "console_scripts": [
            "vaultak-sentry=vaultak_sentry_runner:main",
        ],
    },
    install_requires=["psutil>=5.9.0", "watchdog>=3.0.0"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
