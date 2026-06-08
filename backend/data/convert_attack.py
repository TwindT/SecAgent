import json
from pathlib import Path

def convert_attack_stix_to_simple(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as f:
        stix_data = json.load(f)
    
    objects = stix_data.get('objects', [])
    
    tactics = {}
    techniques = {}
    
    for obj in objects:
        obj_type = obj.get('type')
        
        if obj_type == 'x-mitre-tactic':
            tactic_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    tactic_id = ref.get('external_id')
                    break
            
            if tactic_id:
                tactics[tactic_id] = {
                    'id': tactic_id,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'techniques': []
                }
        
        elif obj_type == 'attack-pattern':
            technique_id = None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id')
                    break
            
            if technique_id and not obj.get('x_mitre_deprecated', False):
                keywords = obj.get('x_mitre_keywords', [])
                techniques[technique_id] = {
                    'id': technique_id,
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'keywords': keywords
                }
    
    for obj in objects:
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
            source_ref = obj.get('source_ref', '')
            target_ref = obj.get('target_ref', '')
            
            source_id = None
            target_id = None
            
            for item in objects:
                if item.get('id') == source_ref:
                    for ref in item.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            source_id = ref.get('external_id')
                            break
                if item.get('id') == target_ref:
                    for ref in item.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            target_id = ref.get('external_id')
                            break
            
            if source_id in tactics and target_id in techniques:
                technique_copy = techniques[target_id].copy()
                technique_copy['tactic_id'] = source_id
                technique_copy['tactic_name'] = tactics[source_id]['name']
                tactics[source_id]['techniques'].append(technique_copy)
    
    result = {
        'version': stix_data.get('spec_version', '2.1'),
        'tactics': list(tactics.values())
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"Conversion complete!")
    print(f"Total tactics: {len(result['tactics'])}")
    total_techniques = sum(len(t['techniques']) for t in result['tactics'])
    print(f"Total techniques: {total_techniques}")

if __name__ == "__main__":
    input_file = Path(__file__).parent / "enterprise-attack.json"
    output_file = Path(__file__).parent / "attack.json"
    
    if not input_file.exists():
        print(f"Error: Input file not found at {input_file}")
        exit(1)
    
    convert_attack_stix_to_simple(input_file, output_file)
    print(f"Output written to {output_file}")