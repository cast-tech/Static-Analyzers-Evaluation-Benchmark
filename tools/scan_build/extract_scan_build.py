from tools.extractors import SARIFExtractor
from tools.base import CweTypes


RULE_IDS = {
    CweTypes.MEMORY_LEAK.value: [
        "unix.Malloc", "cplusplus.NewDeleteLeaks",
    ],
    CweTypes.DOUBLE_FREE.value: [
        "unix.Malloc", "cplusplus.NewDelete",
    ],
    CweTypes.USE_AFTER_FREE.value: [
        "unix.Malloc", "cplusplus.NewDelete",
        "cplusplus.InnerPointer", "cplusplus.Move",
    ],
}

CWE_MESSAGES = {
    CweTypes.MEMORY_LEAK.value: "Potential leak of memory pointed to by",
    CweTypes.DOUBLE_FREE.value: "Attempt to free released memory",
    CweTypes.USE_AFTER_FREE.value: "Use of memory after it is freed",
}

class ScanBuildExtractor(SARIFExtractor):
    RULE_IDS = RULE_IDS
    CWE_MESSAGES = CWE_MESSAGES
    MESSAGE_FILTERED_RULES = {"unix.Malloc", "cplusplus.NewDelete"}

    def _process_result(self, _result_file_path, res, _cwe_type):
        file_path_uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        file_path = self._get_path_from_url(file_path_uri)
        file_path = self._normalize_path(file_path)
        if file_path not in self.sources:
            return
        code_flows = res.get("codeFlows") or []
        if not code_flows:
            return
        first_function_location = code_flows[0]["threadFlows"][0]["locations"][0]["location"]
        first_function_name = self._get_function_name_from_msg(first_function_location["message"]["text"])
        if first_function_name is None:
            return
        self.results[file_path].append(first_function_name)
