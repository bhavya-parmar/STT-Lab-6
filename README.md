# STT-Lab-6 - Evaluation of Vulnerability Analysis Tools using CWE-based Comparison

By Bhavya Parmar (23110059)

## Overview

This repository evaluates multiple vulnerability analysis tools using a CWE-based comparison. It aims to assess how well different tools detect and report software vulnerabilities, referencing the Common Weakness Enumeration (CWE) framework.

## Directory Structure

- `analysis.ipynb`  
  Jupyter notebook for analyzing vulnerability scan results.

- `parse_convert.py`  
  Python script for parsing and converting tool outputs to a consolidated format.

- `consolidated_csv.csv`  
  CSV file containing merged vulnerability data.

- `codeql.sh`, `semgrep.ipynb`, `snyk.sh`  
  Scripts and notebooks for running CodeQL, Semgrep, and Snyk scans.

- `logs/`  
  Directory for storing scan logs and outputs of each tool.

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd STT-Lab-6
   ```
2. **Clone Repositories to be Analyzed:**
    ```sh
    git clone <repo-url>
    ```
    I have used the following the repositories:
   - [Agno](https://github.com/agno-agi/agno)
   - [Altair](https://github.com/vega/altair)
   - [Androguard](https://github.com/androguard/androguard)

3. **Run vulnerability scans:**
   Execute the provided scripts for each tool: `codeql.sh`, `semgrep.ipynb`, and `snyk.sh` to generate scan results.

4. **Parse and consolidate results:**
   Use `parse_convert.py` to merge the outputs into `consolidated_csv.csv`.

5. **Analyze results:**
   Open `analysis.ipynb` in Jupyter Notebook to visualize and analyze the consolidated data.