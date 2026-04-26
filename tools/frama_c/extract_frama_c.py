import os
from os.path import dirname

from tools.extractors import SARIFExtractor, SourceFunctionExtractor
from tools.base import CweTypes

RULE_IDS = {
    CweTypes.DOUBLE_FREE.value: [
        "dangling_pointer",
    ],
    CweTypes.USE_AFTER_FREE.value: [
        "dangling_pointer",
    ],
}

FRAMA_C_CWE_MESSAGES = {
    CweTypes.DOUBLE_FREE.value: "dangling_pointer.",
    CweTypes.USE_AFTER_FREE.value: "dangling_pointer.",
}


class FramaCExtractor(SARIFExtractor):
    RULE_IDS = RULE_IDS
    CWE_MESSAGES = FRAMA_C_CWE_MESSAGES

    def _is_result_for_cwe(self, res, cwe_type) -> bool:
        if res.get("ruleId") not in self.RULE_IDS.get(cwe_type, []):
            return False
        return res["message"]["text"].startswith(self.CWE_MESSAGES[cwe_type])

    def _process_result(self, _result_file_path, res, _cwe_type):
        file_path_uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        file_path = self._get_path_from_url(file_path_uri)
        file_path = self._normalize_path(file_path)
        if file_path not in self.sources:
            return
        start_line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
        function_name = self._get_function_by_line(file_path, start_line)

        if function_name.endswith("badSink") or function_name.endswith("bad") or function_name.endswith(
                "badSource") or function_name.endswith("Bad"):
            file_path = self.update_to_main_file(file_path)
            file_path = self._normalize_path(file_path)
            real_path = self._get_real_path(file_path)
            extractor = SourceFunctionExtractor(real_path)
            for cur_func in extractor.extract_functions_from_src():
                if cur_func.name.endswith("_bad"):
                    function_name = cur_func.name
                    break

        self.results[file_path].append(function_name)
