import json, csv, re
from pathlib import Path
from collections import defaultdict

CWE_RE = re.compile(r"CWE-(\d+)")
ENCODINGS = ("utf-8", "utf-16", "utf-8-sig")

def load_json(p: Path):
    for enc in ENCODINGS:
        try:
            return json.loads(p.read_text(encoding=enc))
        except UnicodeError:
            continue
        except json.JSONDecodeError:
            break
    return None

def detect_tool(data):
    if isinstance(data, dict):
        if "runs" in data:
            # Check SARIF structure
            for run in data.get("runs", []):
                tool_name = run.get("tool", {}).get("driver", {}).get("name", "").lower()
                if "snyk" in tool_name:
                    return "snyk"
                if "codeql" in tool_name:
                    return "codeql"
        if "results" in data:
            # Check Semgrep structure
            for r in data.get("results", []):
                if "extra" in r and "metadata" in r["extra"] and "cwe" in r["extra"]["metadata"]:
                    return "semgrep"
    return "unknown"

def extract_project_name(file_path: Path):
    stem = file_path.stem.lower()
    for prefix in ("snyk_", "semgrep_", "codeql_"):
        if stem.startswith(prefix):
            return stem[len(prefix):]
    return file_path.parent.name

def extract_snyk(data):
    # SARIF structure
    cwe_counts = defaultdict(int)
    for run in data.get("runs", []):
        rule_map = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rid = rule.get("id")
            cwes = []
            raw = rule.get("properties", {}).get("cwe", [])
            if isinstance(raw, str):
                raw = [raw]
            for entry in raw:
                for m in CWE_RE.findall(str(entry)):
                    cwes.append(f"CWE-{int(m)}")
            if cwes:
                rule_map[rid] = cwes
        for result in run.get("results", []):
            rid = result.get("ruleId")
            for cwe in rule_map.get(rid, []):
                cwe_counts[cwe] += 1
    return cwe_counts

def extract_semgrep(data):
    cwe_counts = defaultdict(int)
    for r in data.get("results", []):
        raw = r.get("extra", {}).get("metadata", {}).get("cwe")
        if raw is None: continue
        if not isinstance(raw, (list, tuple)):
            raw = [raw]
        for item in raw:
            for m in CWE_RE.findall(str(item)):
                cwe_counts[f"CWE-{int(m)}"] += 1
    return cwe_counts

def extract_codeql(data):
    # CodeQL SARIF structure
    cwe_counts = defaultdict(int)

    # Map ruleId -> tags
    rule_tags = {}
    for run in data.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            tags = rule.get("properties", {}).get("tags", [])
            rule_id = rule.get("id")
            rule_tags[rule_id] = tags

    # Extract CWE IDs from results
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            tags = rule_tags.get(rule_id, [])
            for tag in tags:
                tag_lower = tag.lower()
                if "cwe-" in tag_lower:
                    cwe_id = tag_lower.split("/")[-1].upper()
                    if CWE_RE.match(cwe_id):
                        cwe_counts[cwe_id] += 1

    return cwe_counts

EXTRACTORS = {
    "snyk": extract_snyk,
    "semgrep": extract_semgrep,
    "codeql": extract_codeql
}

def gather_logs(logs_path: Path):
    files = []
    for subfolder in ["codeql", "semgrep", "snyk"]:
        folder_path = logs_path / subfolder
        if folder_path.is_dir():
            files.extend(folder_path.rglob("*.json"))
            files.extend(folder_path.rglob("*.sarif"))
    return files

def main():
    logs_path = Path("logs")  # Automatically traverse the logs folder
    out_path = Path("consolidated_cwe.csv")

    top25 = [
        "CWE-79", "CWE-787", "CWE-89", "CWE-352", "CWE-22", "CWE-125", "CWE-78", "CWE-416",
        "CWE-862", "CWE-434", "CWE-94", "CWE-20", "CWE-77", "CWE-287", "CWE-269", "CWE-502",
        "CWE-200", "CWE-863", "CWE-918", "CWE-119", "CWE-476", "CWE-798", "CWE-190", "CWE-400", "CWE-306"
    ]

    rows = []
    for f in gather_logs(logs_path):
        data = load_json(f)
        if data is None:
            continue
        tool = detect_tool(data)
        if tool not in EXTRACTORS:
            continue
        project = extract_project_name(f)
        counts = EXTRACTORS[tool](data)
        for cwe, n in counts.items():
            rows.append((project, tool, cwe, n, "Yes" if cwe in top25 else "No"))

    rows.sort()
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Project_name", "Tool_name", "CWE_ID", "Number of Findings", "Is_In_CWE_Top_25"])
        w.writerows(rows)
    print(f"Wrote {out_path} ({len(rows)} rows)")

if __name__ == "__main__":
    main()