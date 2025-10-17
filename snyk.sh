#!/bin/bash

# Using Snyk Code CLI to analyze the different repositories

# install
npm install -g snyk

# Verify Snyk Code is installed
snyk version

# authenticate (opens browser)
snyk auth

# Make sure to run this script from the directory containing the repositories: agno, altair, androguard (clone them if not already done)

# Analyze the agno repository
cd agno
snyk code test --json > snyk_agno.json

# Analyze the altair repository
cd ../altair
snyk code test --json > snyk_altair.json

# Analyze the androguard repository
cd ../androguard
snyk code test --json > snyk_androguard.json