#!/usr/bin/env python

try:
    from setuptools import setup, find_packages
    extra = dict(install_requires=[
        'boto>=2.38.0',
        'mrjob>=0.4.5',
    ],
        include_package_data=True,
    )
except ImportError:
    from distutils.core import setup
    extra = {}


def readme():
    with open("README.rst") as f:
        return f.read()


setup(name="ucsd-bigdata",
      version="1.0.2",
      description="Scripts for the UCSD MAS Data Science and Engineering program",
      long_description=readme(),
      author="UCSD MAS Data Science and Engineering program",
      author_email="",
      scripts=[
          "bin/ucsd-bigdata-setup.py",
          "bin/find_waiting_flow.py",
          "bin/get_emr_logs.py",
          "bin/github_add_ssh_key.py",
          "bin/launch_notebook_server.py",
          "bin/vault.py",
      ],
      url="https://github.com/mas-dse/UCSD_BigData_Scripts",
      packages=[
          "ucsd_bigdata",
      ],
      package_data={
          "ucsd_bigdata": ["templates/mrjob.conf"],
      },
      platforms="Posix; MacOS X",
      classifiers=[
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
      ],
      **extra
      )
