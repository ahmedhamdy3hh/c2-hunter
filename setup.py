from setuptools import setup, find_packages

setup(
    name="c2-hunter",
    version="1.0.0",
    description="Cross-platform CLI cybersecurity tool to detect C2 beaconing activity in network traffic.",
    author="C2-Hunter Cybersecurity Team",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "c2-hunter=c2_hunter.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
