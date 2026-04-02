from collections import defaultdict
from collections.abc import Iterable


class DuplicateDetector:
    def find_duplicates(self, values: Iterable[str]) -> dict[str, list[str]]:
        index = defaultdict(list)
        for value in values:
            index[value].append(value)
        return {k: v for k, v in index.items() if len(v) > 1}
