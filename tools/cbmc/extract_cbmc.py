import json
import os
from os.path import dirname

from tools.extractors import FunctionExtractor
from tools.base import CweTypes

from tools.support import get_files_from_dir_with_patterns

RULE_DESC = {
    CweTypes.MEMORY_LEAK.value:
        ["dynamically allocated memory never freed in"],
    CweTypes.DOUBLE_FREE.value:
        ["double free",
         "double delete"],
    CweTypes.USE_AFTER_FREE.value:
        ["dereference failure"]
}

CBMC_CWE_status = {
    CweTypes.MEMORY_LEAK.value: "FAILURE",
    CweTypes.DOUBLE_FREE.value: "FAILURE",
    CweTypes.USE_AFTER_FREE.value: "FAILURE",
}

CUR_DIR = dirname(os.path.realpath(os.path.abspath(__file__)))


class CbmcExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        res_file_pattern = "**/*.json"

        return get_files_from_dir_with_patterns(result_dir, [res_file_pattern])

    @staticmethod
    def _is_status_for_cwe(res, cwe_type):
        message = res['status']
        if message != CBMC_CWE_status[cwe_type]:
            return False
        return True

    @staticmethod
    def _is_rule_description_for_cwe(description, cwe_type):
        for desc in RULE_DESC[cwe_type]:
            if description == desc or description.startswith(desc):
                return True
        return False

    def extract(self, result_file_path, cwe_type):
        try:
            with open(result_file_path, 'r') as res_file:
                result_file = json.load(res_file)
            for elem in result_file:
                if 'result' in elem:
                    for report in elem['result']:
                        if (self._is_status_for_cwe(report, cwe_type)
                                and self._is_rule_description_for_cwe(report['description'], cwe_type)):
                            function_name = ""
                            file_path = ""
                            for trace in report['trace']:
                                if ('sourceLocation' in trace) and ('function' in trace['sourceLocation']) and (
                                        'file' in trace['sourceLocation']):
                                    if trace['sourceLocation']['function'] != "main" or not trace['sourceLocation'][
                                        'function'].startswith("main"):
                                        function_name = trace['sourceLocation']['function']
                                        file_path = trace['sourceLocation']['file']
                                        file_path = self._get_real_path(file_path)
                                        file_path = self._normalize_path(file_path)
                                        if file_path in self.sources:
                                            if function_name.endswith("bad") or function_name == "bad":
                                                break

                            if function_name and file_path in self.sources:
                                self.results[file_path].append(function_name)

        except json.JSONDecodeError:
            self.invalid_json.append(result_file_path)