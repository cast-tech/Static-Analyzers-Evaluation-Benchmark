from tools.base import CweTypes
from tools.extractors import FunctionExtractor
from tools.classifier import ResultClassifier, FunctionTypes
from tools.support import get_files_from_dir_with_patterns
import cxxfilt
import os.path
import re

CWE_TO_ERROR_MESSAGE = {
    CweTypes.DOUBLE_FREE.value: "memory error: double free",
    CweTypes.USE_AFTER_FREE.value: "memory error: use after free",
}


def check_cwe(cwe_type, error_message):
    expected_message = CWE_TO_ERROR_MESSAGE[cwe_type]
    return expected_message in error_message


def demangle(mangled_name: str):
    removed_parameters = mangled_name.split('(', 1)[0]
    try:
        demangled_name = cxxfilt.demangle(removed_parameters)
    except cxxfilt.InvalidName:
        demangled_name = removed_parameters
    removed_parameters_again = demangled_name.split('(', 1)[0]
    removed_namespace = re.sub(r'.*::', '', removed_parameters_again)

    return removed_namespace[1:] if removed_namespace.startswith('~') else removed_namespace


class KleeExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        res_file_pattern = "**/*.ptr.err"

        return get_files_from_dir_with_patterns(result_dir, [res_file_pattern])

    def extract(self, result_file_path, cwe_type):
        with open(result_file_path, "r", encoding="utf-8") as file:
            file_content = file.read()

        error_match = re.search(r"Error:\s*(.+)", file_content)
        error_message = error_match.group(1) if error_match else "Unknown error"

        if not check_cwe(cwe_type, error_message):
            return

        stack_matches = re.findall(r"#\d+\s+in\s+(.+?)\s+at\s+(.+?):\d+", file_content)
        stack_info = [(file, demangle(func)) for func, file in stack_matches]

        for file_path, function in stack_info:
            abs_path = os.path.abspath(file_path)
            abs_path = self._normalize_path(abs_path)
            if (ResultClassifier._function_is_type(function, FunctionTypes.BAD, self.language)
                    and abs_path in self.results):
                self.results[abs_path].append(function)
                return

        first_file_path, first_function = stack_info[0]
        first_file_path = self._normalize_path(first_file_path)
        if first_file_path in self.results:    # False positive case
            self.results[first_file_path].append(first_function)
