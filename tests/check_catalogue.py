from pathlib import Path
import json
import re
import sys

root = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Canonical finding-class catalogue
# ---------------------------------------------------------------------------

schema = json.loads(
    (root / "schema/unified_security_finding.schema.json").read_text()
)

classes = schema["properties"]["finding_class"]["enum"]
catalogue = set(classes)

# ---------------------------------------------------------------------------
# Scanner -> finding-class mappings
# ---------------------------------------------------------------------------

mapping = json.loads(
    (root / "scanner_orchestrators/finding_class_mapping.json").read_text()
)

mapped = {
    finding_class
    for values in mapping.values()
    for finding_class in values
}

# ---------------------------------------------------------------------------
# Remediation-rule seed
#
# The seed contains:
#   - one generic remediation rule for each canonical finding class
#   - optional specialised deterministic rules for narrower matches
#
# Specialised rules must therefore NOT be treated as a violation of the
# 43-class catalogue.
# ---------------------------------------------------------------------------

rules_sql = (
    root / "database/003_seed_remediation_rules.sql"
).read_text()

# Capture every seeded remediation-rule row.
#
# The first two string values in each row are:
#   rule_name, finding_class
all_rule_pairs = re.findall(
    r"^\('([^']+)','([a-z0-9_]+)'",
    rules_sql,
    flags=re.MULTILINE,
)

all_rule_names = [rule_name for rule_name, _ in all_rule_pairs]
all_rule_classes = [
    finding_class
    for _, finding_class in all_rule_pairs
]

all_rule_class_set = set(all_rule_classes)

# Generic rules are the baseline coverage invariant:
# every canonical finding class must have a generic rule.
generic_rule_pairs = [
    (rule_name, finding_class)
    for rule_name, finding_class in all_rule_pairs
    if rule_name.endswith("_generic")
]

generic_rule_classes = {
    finding_class
    for _, finding_class in generic_rule_pairs
}

# ---------------------------------------------------------------------------
# Consistency checks
# ---------------------------------------------------------------------------

duplicate_rule_names = sorted({
    rule_name
    for rule_name in all_rule_names
    if all_rule_names.count(rule_name) > 1
})

problems = {
    "catalogue_count": len(classes),
    "seeded_rule_count": len(all_rule_pairs),
    "generic_rule_count": len(generic_rule_pairs),
    "unique_rule_class_count": len(all_rule_class_set),
    "mapped_unique_count": len(mapped),

    "missing_generic_rules": sorted(
        catalogue - generic_rule_classes
    ),

    "unknown_rule_classes": sorted(
        all_rule_class_set - catalogue
    ),

    "unknown_scanner_classes": sorted(
        mapped - catalogue
    ),

    "unmapped_catalogue_classes": sorted(
        catalogue - mapped
    ),

    "duplicate_rule_names": duplicate_rule_names,
}

for key, value in problems.items():
    print(f"{key}: {value}")

# ---------------------------------------------------------------------------
# Required invariants
# ---------------------------------------------------------------------------

if (
    len(classes) != 43
    or len(generic_rule_pairs) != 43
    or problems["missing_generic_rules"]
    or problems["unknown_rule_classes"]
    or problems["unknown_scanner_classes"]
    or problems["unmapped_catalogue_classes"]
    or problems["duplicate_rule_names"]
):
    sys.exit(1)

print(
    "OK: exact 43-class catalogue, generic rule coverage, "
    "specialised remediation rules and scanner mappings are consistent."
)
