#!/bin/bash

# Using CodeQL CLI to analyze the different repositories

# Verify CodeQL is installed
codeql version 

# Install necessary CodeQL packs
codeql pack download codeql/python-queries      

# Make sure to run this script from the directory containing the repositories: agno, altair, androguard (clone them if not already done)

# Analyze the agno repository
cd agno
codeql database create agno-db --language=python --source-root=.  
codeql database analyze agno-db codeql/python-queries:codeql-suites/python-security-and-quality.qls --format=sarifv2.1.0 --output=codeql_agno.sarif
# The results will be in codeql_agno.sarif file in the agno folder

# Analyze the altair repository
cd ../altair
codeql database create altair-db --language=python --source-root=.  
codeql database analyze altair-db codeql/python-queries:codeql-suites/python-security-and-quality.qls --format=sarifv2.1.0 --output=codeql_altair.sarif

# Analyze the androguard repository
cd ../androguard
codeql database create androguard-db --language=python --source-root=.  
codeql database analyze androguard-db codeql/python-queries:codeql-suites/python-security-and-quality.qls --format=sarifv2.1.0 --output=codeql_androguard.sarif