#!/usr/bin/env python

from setuptools import setup, find_packages

import pcap2har

setup(
    name="pcap2har",
    version=pcap2har.__version__,
    description="PCAP to HAR conversion utility",
    long_description="A simple tool to generate HTTP Archive (HAR) files from PCAP-formatted network capture data.",
    author="Andrew Fleenor",
    author_email="no@reply.com",
    maintainer="Jordan Carlson",
    maintainer_email="jwgcarlson@gmail.com",
    url="https://github.com/jwgcarlson/pcap2har",
    packages=find_packages(),
    scripts=["bin/pcap2har"],
)
