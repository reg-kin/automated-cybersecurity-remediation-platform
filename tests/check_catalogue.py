from pathlib import Path
import json
import re
import sys

root = Path(__file__).resolve().parents[1]

schema = json.loads(
    (root / "schema/unified_security_finding.schema.json").read_text()
)
classes = schema["properties"]["finding_class"]["enum"]

mapping = json.loads(
    (root / "scanner_orchestrators/finding_class_mapping.json").read_text()
)

rules_sql = (root / "database/003_seed_remediation_rules.sql").read_text()

rule_classes = set(
    re.findall(r"'([a-z0-9_]+)_generic','([a-z0-9_]+)'", rules_sql)
)
rule_values = {finding_class for _, finding_class in rule_classes}
mapped = {item for values in mapping.values() for item in values}

problems = {
    "catalogue_count": len(classes),
    "rule_count": len(rule_values),
    "mapped_unique_count": len(mapped),
    "missing_rules": sorted(set(classes) - rule_values),
    "extra_rules": sorted(rule_values - set(classes)),
    "unknown_scanner_classes": sorted(mapped - set(classes)),
    "unmapped_catalogue_classes": sorted(set(classes) - mapped),
}

for key, value in problems.items():
    print(f"{key}: {value}")

if (
    len(classes) != 43
    or problems["missing_rules"]
    or problems["extra_rules"]
    or problems["unknown_scanner_classes"]
    or problems["unmapped_catalogue_classes"]
):
    sys.exit(1)

print("OK: exact 43-class catalogue, rules and scanner mappings are consistent.")
