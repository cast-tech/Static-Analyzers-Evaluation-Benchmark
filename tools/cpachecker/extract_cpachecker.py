from tools.extractors import FunctionExtractor
from tools.support import get_files_from_dir_with_patterns
from tools.base import CweTypes
import os.path

PATH_TO_SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CPACHECKER_CWE_MESSAGES = {
    CweTypes.MEMORY_LEAK.value: "Verification result: FALSE. Property violation (valid-memtrack",
    CweTypes.DOUBLE_FREE.value: "Verification result: FALSE. Property violation (valid-free",
    CweTypes.USE_AFTER_FREE.value: "Verification result: FALSE. Property violation (valid-deref",
}


def is_message_for_cwe(message: str, cwe_type: str) -> bool:
    return message.startswith(CPACHECKER_CWE_MESSAGES[cwe_type])


def get_verification_result_line(file_path: str):
    with open(file_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos = f.tell()
        while pos > 0:
            f.seek(pos - 1)
            char = f.read(1)
            if char == b"\n":
                line = f.readline().decode().strip()
                if line.startswith("Verification result:"):
                    return line
            pos -= 1
    return ""


class CpacheckerExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        res_file_pattern = "**/*.core.txt"
        files = get_files_from_dir_with_patterns(result_dir, [res_file_pattern])
        return files

    def extract(self, result_file_path, cwe_type):
        testcase_path = os.path.dirname(result_file_path)
        testcase_name = os.path.basename(testcase_path)
        stats_path = os.path.join(testcase_path, "Statistics.txt")

        message = get_verification_result_line(stats_path)
        if not message or not is_message_for_cwe(message, cwe_type):
            # print(f"For the test case {testcase_name}, "
            #       f"no result message or it is not matching with CWE type: {cwe_type}\n"
            #       f"Results for the test case will be ignored! Message: {message}")
            return

        with open(result_file_path, "r", encoding="utf-8") as file:
            result_content = file.read()

        source_file = self.get_source_file_from_function(testcase_name)
        if not source_file:
            print(f"Warning: Could not find the source file for the test case {testcase_name}\n"
                  f"Results for the test case will be ignored. Consider checking this case manually.")
            return
        source_file = self._normalize_path(source_file)
        if testcase_name in result_content:
            self.results[source_file].append(testcase_name)
        else:
            print(f"Warning: Don't know what function to report for the test case {testcase_name}\n"
                  f"Results for the test case will be ignored. Consider checking this case manually. Message: {message}")