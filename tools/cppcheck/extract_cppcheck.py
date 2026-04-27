from tools.extractors import SARIFExtractor
from tools.base import CweTypes


RULE_IDS = {
    CweTypes.MEMORY_LEAK.value: [
        "memleak",
    ],
    CweTypes.DOUBLE_FREE.value: [
        "doubleFree",
    ],
    CweTypes.USE_AFTER_FREE.value: [
        "deallocuse",
    ],
}


class CppcheckExtractor(SARIFExtractor):
    RULE_IDS = RULE_IDS

    def _process_result(self, _result_file_path, res, _cwe_type):
        uri_src = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        src = self._get_path_from_url(uri_src)
        src = self._normalize_path(src)
        if src not in self.sources:
            return
        first_function_line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
        first_function_name = self._get_function_by_line(src, first_function_line)
        if first_function_name is None:
            return
        self.results[src].append(first_function_name)
