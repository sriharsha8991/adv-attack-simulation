"""Phase 3 Verification Script — tests GalaxyManager, CTITools, MISPTools."""

import json
import sys
import logging
from pathlib import Path 


logging.basicConfig(level=logging.WARNING)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ── Step 1: Test GalaxyManager ────────────────────────────────

print("=" * 60)
print("Step 1: GalaxyManager — Download & Parse MISP Galaxies")
print("=" * 60)

from src.layers.layer2_enrichment import GalaxyManager

gm = GalaxyManager()
counts = gm.load_all()

print("\nLoad counts:")
for k, v in counts.items():
    print(f"  {k}: {v}")

print("\nStats:")
for k, v in gm.stats().items():
    print(f"  {k}: {v}")

# Test T1003 lookup
ctx = gm.get_technique_context("T1003")
ap = ctx["attack_pattern"]
print(f"\nT1003 Galaxy Context:")
print(f"  Attack Pattern: {ap['name'] if ap else 'None'}")
print(f"  Groups: {len(ctx['groups'])}")
print(f"  Tools: {len(ctx['tools'])}")
print(f"  Malware: {len(ctx['malware'])}")
if ctx["groups"]:
    print(f"  Sample groups: {[g['name'] for g in ctx['groups'][:5]]}")
if ctx["tools"]:
    print(f"  Sample tools:  {[t['name'] for t in ctx['tools'][:5]]}")

# ── Step 2: Test CTITools ─────────────────────────────────────

print("\n" + "=" * 60)
print("Step 2: CTITools — Neo4j Knowledge Graph Queries")
print("=" * 60)

from src.tools.cti_tools import CTITools

with CTITools() as cti:
    # get_intrusion_sets_for_technique
    groups = cti.get_intrusion_sets_for_technique("T1003")
    print(f"\nIntrusion sets for T1003: {len(groups)}")
    for g in groups[:5]:
        print(f"  - {g['group_name']}")

    # get_tools_for_technique
    tools = cti.get_tools_for_technique("T1003.001")
    print(f"\nTools for T1003.001: {len(tools)}")
    for t in tools[:5]:
        print(f"  - {t['name']} ({t['type']})")

    # get_detection_guidance
    det = cti.get_detection_guidance("T1003")
    print(f"\nDetection for T1003:")
    print(f"  Data sources: {det['data_sources']}")
    det_text = det["detection_text"]
    if det_text:
        print(f"  Detection text: {det_text[:150]}...")

    # get_mitigations
    mits = cti.get_mitigations("T1003")
    print(f"\nMitigations for T1003: {len(mits)}")
    for m in mits[:5]:
        print(f"  - {m['mitigation_name']}")

    # get_full_technique_context
    full = cti.get_full_technique_context("T1003")
    print(f"\nFull T1003 context:")
    print(f"  Name:        {full.get('name')}")
    print(f"  Attack ID:   {full.get('attack_id')}")
    print(f"  Tactics:     {full.get('tactics')}")
    print(f"  Groups:      {len(full.get('groups', []))}")
    print(f"  Tools:       {len(full.get('tools', []))}")
    print(f"  Mitigations: {len(full.get('mitigations', []))}")

# ── Step 3: Test MISPTools ────────────────────────────────────

print("\n" + "=" * 60)
print("Step 3: MISPTools — End-to-End Enrichment")
print("=" * 60)

from src.tools.misp_tools import MISPTools

with MISPTools(galaxy_manager=gm) as misp:
    # search_misp_galaxy
    galaxy_results = misp.search_misp_galaxy("T1003")
    print(f"\nMISP Galaxy search for T1003:")
    print(f"  Groups:  {len(galaxy_results.get('groups', []))}")
    print(f"  Tools:   {len(galaxy_results.get('tools', []))}")
    print(f"  Malware: {len(galaxy_results.get('malware', []))}")

    # enrich_technique_context → ThreatIntelContext
    tic = misp.enrich_technique_context("T1003")
    print(f"\nThreatIntelContext for T1003:")
    print(f"  associated_groups:  {tic.associated_groups[:5]}")
    print(f"  associated_tools:   {tic.associated_tools[:5]}")
    print(f"  recent_campaigns:   {tic.recent_campaigns[:3]}")
    det_g = tic.detection_guidance or ""
    print(f"  detection_guidance: {det_g[:150]}...")

    # JSON export roundtrip
    tic_json = tic.model_dump_json(indent=2)
    print(f"\n  JSON export size: {len(tic_json)} bytes")
    tic_roundtrip = json.loads(tic_json)
    assert "associated_groups" in tic_roundtrip
    assert "associated_tools" in tic_roundtrip
    print("  JSON roundtrip: OK")

print("\n" + "=" * 60)
print("Phase 3 Verification: ALL CHECKS PASSED")
print("=" * 60)
