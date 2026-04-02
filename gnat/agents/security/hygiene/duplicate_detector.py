from collections import defaultdict
from typing import Dict, Iterable, List

class DuplicateDetector:
    def find_duplicates(self, values: Iterable[str]) -> Dict[str, List[str]]:
        index = defaultdict(list)
        for value in values: index[value].append(value)
        return {k: v for k, v in index.items() if len(v) > 1}
