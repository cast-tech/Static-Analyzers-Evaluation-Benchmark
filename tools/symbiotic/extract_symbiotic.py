import os
from os.path import dirname

from tools.extractors import FunctionExtractor, SourceFunctionExtractor
from tools.base import CweTypes

from tools.support import get_files_from_dir_with_patterns

SYMBIOTIC_CWE_MESSAGES = {
    CweTypes.MEMORY_LEAK.value: "memory error: memory leak detected",
    CweTypes.DOUBLE_FREE.value: "memory error: invalid pointer: free",
}

CUR_DIR = dirname(os.path.realpath(os.path.abspath(__file__)))

import re

class SymbioticExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        res_file_pattern = "**/*.txt"

        return get_files_from_dir_with_patterns(result_dir, [res_file_pattern])

    @staticmethod
    def _is_message_for_cwe(res, cwe_type):
        message = res
        if not message.startswith(SYMBIOTIC_CWE_MESSAGES[cwe_type]):
            return False
        return True

    @staticmethod
    def parse_error_report(filename):
        with open(filename, "r", encoding="utf-8") as file:
            report = file.read()

        error_traces = report.split("\n --- Error trace ---\n")

        error_pattern = re.compile(r"Error: (.*?)\nFile: (.*?)\nLine: (\d+)", re.DOTALL)
        stack_pattern = re.compile(r"#\d+\s+in\s+([\w\d_]+)\s*\(", re.DOTALL)

        errors = []

        for trace in error_traces:
            match = error_pattern.search(trace)
            if match:
                error_msg, file_path, line_number = match.groups()

                stack_match = stack_pattern.findall(trace)
                function_names = []
                if stack_match:
                    function_names = stack_match
                if len(function_names) == 1:
                    function_match = re.search(r"allocated at (\w+)\(\)", trace)
                    called_function = function_match.group(1)
                    if function_match:
                        function_names.append(called_function)

                errors.append({
                    "error_message": error_msg.strip(),
                    "file_path": file_path.strip(),
                    "line_number": line_number.strip(),
                    "function_names": function_names
                })

        return errors

    def extract(self, result_file_path, cwe_type):
        errors = self.parse_error_report(result_file_path)
        for error in errors:
            if self._is_message_for_cwe(error['error_message'], cwe_type):
                if  error['function_names'] != "Not found" :
                    function_name = error['function_names'][len(error['function_names']) - 1]
                    file_path = self._normalize_path(error['file_path'])
                    file_path = self.update_to_main_file(file_path)

                    for function_name_cur in error['function_names']:
                        if function_name_cur.endswith("_bad"):
                            function_name = function_name_cur
                            break
                        if function_name.endswith("badSink") or function_name.endswith("bad") or function_name.endswith(
                                "badSource") or function_name.endswith("Bad"):
                            real_path = self._get_real_path(file_path)
                            extractor = SourceFunctionExtractor(real_path)
                            for cur_func in extractor.extract_functions_from_src():
                                cur_func_name: str = cur_func.name
                                if cur_func_name.endswith("_bad"):
                                    function_name = cur_func_name

                    if file_path in self.sources:
                        self.results[file_path].append(function_name)
