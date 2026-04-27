from tools.extractors import SARIFExtractor
from tools.base import CweTypes


RULE_IDS = {
    CweTypes.MEMORY_LEAK.value: [
        "MEMORY_LEAK_C", "MEMORY_LEAK_CPP",
    ],
    CweTypes.USE_AFTER_FREE.value: [
        "USE_AFTER_FREE", "USE_AFTER_FREE_LATENT",
        "USE_AFTER_DELETE", "USE_AFTER_DELETE_LATENT",
    ],
}


class InferExtractor(SARIFExtractor):
    RULE_IDS = RULE_IDS

    def _process_result(self, result_file_path, res, _cwe_type):
        uri_src = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        src = self._reg_uri_to_real(result_file_path, uri_src)
        src = self._normalize_path(src)
        if src not in self.sources:
            return
        if not res.get("codeFlows"):
            return
        first_function_location = res["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
        first_function_line = first_function_location["physicalLocation"]["region"]["startLine"]
        first_function_name = self._get_function_by_line(src, first_function_line)
        if first_function_name is None:
            return
        self.results[src].append(first_function_name)