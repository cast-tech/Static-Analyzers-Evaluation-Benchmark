from tools.extractors import FunctionExtractor
from tools.support import get_files_from_dir_with_patterns
from tools.base import CweTypes
import os.path
import re

PATH_TO_SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SMATCH_CWE_MESSAGES = {
    CweTypes.DOUBLE_FREE.value: "error: double free",
    CweTypes.USE_AFTER_FREE.value: "error: dereferencing freed memory",
}


def is_message_for_cwe(message: str, cwe_type: str) -> bool:
    return message.startswith(SMATCH_CWE_MESSAGES[cwe_type])


def find_reports_location(report: str) -> tuple:
    file_path = None
    function_name = None

    pattern = re.compile("(.+?):(\d+)\s+([a-zA-Z0-9_]+)\(\)\s+error:\s+(.+)")
    match = pattern.match(report)
    if match:
        file_path = match.group(1)
        function_name = match.group(3)
    return file_path, function_name

class SmatchExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        res_file_pattern = "**/*_out.sm"

        return get_files_from_dir_with_patterns(result_dir, [res_file_pattern])

    def extract(self, result_file_path, cwe_type):
        testcase_name = os.path.basename(result_file_path)[:-7]

        with open(result_file_path, "r") as file:
            for line in file:
                if not SMATCH_CWE_MESSAGES[cwe_type] in line:
                    continue
                source_file, function_name = find_reports_location(line)
                if source_file is None or function_name is None:
                    print(f"Warning: Could not parse result message for the testcase: {testcase_name}")
                    continue
                source_file = self._normalize_path(source_file)
                if source_file not in self.results:
                    continue
                self.results[source_file].append(function_name)
