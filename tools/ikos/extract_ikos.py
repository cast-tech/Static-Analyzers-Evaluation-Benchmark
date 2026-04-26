import json
import os
from os.path import dirname

from tools.extractors import FunctionExtractor
from tools.base import CweTypes

RULE_IDS = {

    CweTypes.DOUBLE_FREE.value: [
        "free",
    ],
    CweTypes.USE_AFTER_FREE.value: [
        "buffer-overflow", "begin-buffer-overflow",
        "buffer-overflow-gets", "end-buffer-overflow",
    ],
}

IKOS_CWE_MESSAGES = {
    CweTypes.DOUBLE_FREE.value: "\"double free, pointer",
    CweTypes.USE_AFTER_FREE.value: "\"use after free, pointer",
}

CUR_DIR = dirname(os.path.realpath(os.path.abspath(__file__)))


class IkosExtractor(FunctionExtractor):
    @staticmethod
    def _is_message_for_cwe(res, cwe_type):
        message = res["message"]["text"]
        if not message.startswith(IKOS_CWE_MESSAGES[cwe_type]):
            return False
        return True


    def extract(self, result_file_path, cwe_type):
        with open(result_file_path, 'r') as res_file:
            result_file = json.load(res_file)

        if "runs" not in result_file:
            return

        for run in result_file["runs"]:
            for res in run["results"]:
                if (self._is_message_for_cwe(res, cwe_type)
                        and (res["ruleId"] in RULE_IDS[cwe_type])):

                    file_path_uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    file_path = self._get_path_from_url(file_path_uri)
                    file_path = self._normalize_path(file_path)
                    start_line = res["locations"][0]["physicalLocation"]["region"]["startLine"]
                    first_function_name = self._get_function_by_line(file_path, start_line)

                    frames = res["stacks"][0]["frames"]
                    for loc in frames:
                        file_path_uri_loc = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
                        file_path_loc = self._get_path_from_url(file_path_uri_loc)
                        file_path_loc = self._normalize_path(file_path_loc)
                        start_line_loc = loc["location"]["physicalLocation"]["region"]["startLine"]
                        func_name_loc = self._get_function_by_line(file_path_loc, start_line_loc)
                        if func_name_loc and func_name_loc.endswith("bad"):
                            first_function_name = func_name_loc
                            file_path = file_path_loc
                            break
                    if file_path not in self.sources:
                        for path in self.sources:
                            if file_path.endswith(path):
                                file_path = path
                                break
                        else:
                            continue
                    if first_function_name is None:
                        continue

                    self.results[file_path].append(first_function_name)
