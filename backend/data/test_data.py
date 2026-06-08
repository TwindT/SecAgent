import sys
import io
from pathlib import Path

def test_cwe_data():
    print("=" * 60)
    print("Testing CWE Data...")
    print("=" * 60)
    
    from cwe_loader import CWELoader
    
    loader = CWELoader()
    
    # Test 1: Load data
    data = loader.load()
    assert 'version' in data, "CWE data missing version"
    assert 'cwes' in data, "CWE data missing cwes"
    print(f"OK CWE data loaded successfully (version: {data['version']})")
    
    # Test 2: Get all CWEs
    cwes = loader.get_all_cwes()
    assert len(cwes) > 0, "No CWEs found"
    print(f"OK Found {len(cwes)} CWE entries")
    
    # Test 3: Get CWE by ID
    cwe = loader.get_cwe_by_id("CWE-89")
    assert cwe is not None, "CWE-89 not found"
    assert 'name' in cwe, "CWE missing name"
    assert 'description' in cwe, "CWE missing description"
    print(f"OK CWE-89 found: {cwe['name']}")
    
    # Test 4: Search CWEs
    results = loader.search_cwes("injection")
    assert len(results) > 0, "No CWE search failed"
    print(f"OK Search for 'injection' found {len(results)} results")
    
    # Test 5: Get by severity
    high_cwes = loader.get_cwes_by_severity("High")
    assert len(high_cwes) > 0, "No High severity CWEs found"
    print(f"OK Found {len(high_cwes)} High severity CWEs")
    
    print()
    return True

def test_attack_data():
    print("=" * 60)
    print("Testing ATT&CK Data...")
    print("=" * 60)
    
    from attack_loader import ATTACKLoader
    
    loader = ATTACKLoader()
    
    # Test 1: Load data
    data = loader.load()
    assert 'version' in data, "ATT&CK data missing version"
    assert 'tactics' in data, "ATT&CK data missing tactics"
    print(f"OK ATT&CK data loaded successfully (version: {data['version']})")
    
    # Test 2: Get all tactics
    tactics = loader.get_all_tactics()
    assert len(tactics) > 0, "No tactics found"
    print(f"OK Found {len(tactics)} tactics")
    
    # Test 3: Get all techniques
    techniques = loader.get_all_techniques()
    assert len(techniques) > 0, "No techniques found"
    print(f"OK Found {len(techniques)} techniques")
    
    # Test 4: Get technique by ID
    tech = loader.get_technique_by_id("T1003")
    assert tech is not None, "T1003 not found"
    assert 'name' in tech, "Technique missing name"
    assert 'tactic_name' in tech, "Technique missing tactic name"
    print(f"OK T1003 found: {tech['name']} (Tactic: {tech['tactic_name']})")
    
    # Test 5: Search techniques
    results = loader.search_techniques("phishing")
    assert len(results) > 0, "Technique search failed"
    print(f"OK Search for 'phishing' found {len(results)} results")
    
    # Test 6: Map attack by keywords
    mapped = loader.map_attack_by_keywords(["credential", "dump"])
    assert len(mapped) > 0, "Attack mapping failed"
    print(f"OK Attack mapping found {len(mapped)} matches")
    if mapped:
        print(f"  Best match: {mapped[0]['technique']['id']} - {mapped[0]['technique']['name']}")
    
    print()
    return True

def test_yara_rules():
    print("=" * 60)
    print("Testing YARA Rules...")
    print("=" * 60)
    
    yara_dir = Path(__file__).parent / "yara_rules"
    
    # Test 1: Check directory exists
    assert yara_dir.exists(), "YARA rules directory not found"
    print(f"OK YARA rules directory exists")
    
    # Test 2: Check YARA files
    yara_files = list(yara_dir.glob("*.yar"))
    assert len(yara_files) > 0, "No YARA files found"
    print(f"OK Found {len(yara_files)} YARA rule files")
    
    # List the files
    for yf in yara_files:
        print(f"  - {yf.name}")
    
    print()
    return True

def main():
    print("\n" + "=" * 60)
    print("SecAgent Data Test Suite")
    print("=" * 60)
    print()
    
    try:
        test_cwe_data()
        test_attack_data()
        test_yara_rules()
        
        print("=" * 60)
        print("All tests passed!")
        print("=" * 60)
        return 0
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
