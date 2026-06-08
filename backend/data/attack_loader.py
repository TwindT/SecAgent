import json
from pathlib import Path


class ATTACKLoader:
    def __init__(self, data_path=None):
        if data_path is None:
            data_path = Path(__file__).parent / "attack.json"
        self.data_path = Path(data_path)
        self._data = None

    def load(self):
        if self._data is None:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
        return self._data

    def get_all_tactics(self):
        data = self.load()
        return data.get('tactics', [])

    def get_tactic_by_id(self, tactic_id):
        tactics = self.get_all_tactics()
        for tactic in tactics:
            if tactic.get('id') == tactic_id:
                return tactic
        return None

    def get_all_techniques(self):
        tactics = self.get_all_tactics()
        techniques = []
        for tactic in tactics:
            for tech in tactic.get('techniques', []):
                tech_copy = tech.copy()
                tech_copy['tactic_id'] = tactic['id']
                tech_copy['tactic_name'] = tactic['name']
                techniques.append(tech_copy)
        return techniques

    def get_technique_by_id(self, technique_id):
        techniques = self.get_all_techniques()
        for tech in techniques:
            if tech.get('id') == technique_id:
                return tech
        return None

    def search_techniques(self, keyword):
        techniques = self.get_all_techniques()
        keyword = keyword.lower()
        results = []
        for tech in techniques:
            if (keyword in tech.get('name', '').lower() or 
                keyword in tech.get('description', '').lower() or
                keyword in tech.get('id', '').lower()):
                results.append(tech)
                continue
            for kw in tech.get('keywords', []):
                if keyword in kw.lower():
                    results.append(tech)
                    break
        return results

    def map_attack_by_keywords(self, keywords):
        techniques = self.get_all_techniques()
        matched = []
        for tech in techniques:
            score = 0
            tech_keywords = [kw.lower() for kw in tech.get('keywords', [])]
            for keyword in keywords:
                keyword_lower = keyword.lower()
                if keyword_lower in tech_keywords:
                    score += 2
                if keyword_lower in tech.get('name', '').lower():
                    score += 3
                if keyword_lower in tech.get('description', '').lower():
                    score += 1
            if score > 0:
                matched.append({
                    'technique': tech,
                    'score': score
                })
        matched.sort(key=lambda x: x['score'], reverse=True)
        return matched


if __name__ == "__main__":
    loader = ATTACKLoader()
    print(f"Loaded ATT&CK data version: {loader.load()['version']}")
    print(f"Total tactics: {len(loader.get_all_tactics())}")
    print(f"Total techniques: {len(loader.get_all_techniques())}")
    print()
    
    tech = loader.get_technique_by_id("T1003")
    if tech:
        print(f"T1003: {tech['name']}")
        print(f"Tactic: {tech['tactic_name']}")
        print()
    
    results = loader.search_techniques("phishing")
    print(f"Search results for 'phishing': {len(results)}")
    for r in results:
        print(f"  - {r['id']}: {r['name']}")
    print()
    
    mapped = loader.map_attack_by_keywords(["credential", "dump"])
    print(f"Mapping for ['credential', 'dump']: {len(mapped)}")
    if mapped:
        print(f"  Best match: {mapped[0]['technique']['id']} - {mapped[0]['technique']['name']} (score: {mapped[0]['score']})")
