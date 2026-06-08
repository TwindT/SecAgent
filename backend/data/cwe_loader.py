import json
import os
from pathlib import Path


class CWELoader:
    def __init__(self, data_path=None):
        if data_path is None:
            data_path = Path(__file__).parent / "cwe.json"
        self.data_path = Path(data_path)
        self._data = None

    def load(self):
        if self._data is None:
            with open(self.data_path, 'r', encoding='utf-8') as f:
                self._data = json.load(f)
        return self._data

    def get_all_cwes(self):
        data = self.load()
        return data.get('cwes', [])

    def get_cwe_by_id(self, cwe_id):
        cwes = self.get_all_cwes()
        for cwe in cwes:
            if cwe.get('id') == cwe_id:
                return cwe
        return None

    def search_cwes(self, keyword):
        cwes = self.get_all_cwes()
        keyword = keyword.lower()
        results = []
        for cwe in cwes:
            if (keyword in cwe.get('name', '').lower() or 
                keyword in cwe.get('description', '').lower() or
                keyword in cwe.get('id', '').lower()):
                results.append(cwe)
        return results

    def get_cwes_by_severity(self, severity):
        cwes = self.get_all_cwes()
        return [cwe for cwe in cwes if cwe.get('severity', '').lower() == severity.lower()]


if __name__ == "__main__":
    loader = CWELoader()
    print(f"Loaded CWE data version: {loader.load()['version']}")
    print(f"Total CWEs: {len(loader.get_all_cwes())}")
    print()
    
    cwe = loader.get_cwe_by_id("CWE-89")
    if cwe:
        print(f"CWE-89: {cwe['name']}")
        print(f"Severity: {cwe['severity']}")
        print()
    
    sql_results = loader.search_cwes("sql")
    print(f"Search results for 'sql': {len(sql_results)}")
