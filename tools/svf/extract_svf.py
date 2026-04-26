import os
import re
from os.path import dirname

from tools.extractors import FunctionExtractor, SourceFunctionExtractor
from tools.support import get_files_from_dir_with_patterns
from tools.base import CweTypes

SVF_CWE_PATTERN = {
    CweTypes.MEMORY_LEAK.value: [
        r'NeverFree.*memory allocation at : \([^\{]*\{ "ln": (\d+), "cl": (\d+), "fl": "([^"]+)" \}\)',
        r'PartialLeak.*memory allocation at : \([^\{]*\{ "ln": (\d+), "cl": (\d+), "fl": "([^"]+)" \}\)'],
    CweTypes.DOUBLE_FREE.value: [
        r'Double Free.*memory allocation at : \([^\{]*\{ "ln": (\d+), "cl": (\d+), "fl": "([^"]+)" \}\)'],
}

CUR_DIR = dirname(os.path.realpath(os.path.abspath(__file__)))


class SvfExtractor(FunctionExtractor):
    def collect_result_files(self, result_dir):
        print("collect_result_files, result dir is ", result_dir)
        files = get_files_from_dir_with_patterns(result_dir, ["**/*.svf.txt"])
        return files

    @staticmethod
    def _get_pattern_for_cwe(cwe_type):
        return SVF_CWE_PATTERN.get(cwe_type)

    def extract_file_and_line_from_txt(self, txt_file_path: str, cwe_type: CweTypes):
        with open(txt_file_path, 'r') as file:
            content = file.read()
        patterns = self._get_pattern_for_cwe(cwe_type)
        match_case = []
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                if match:
                    line_number = match.group(1)
                    file_name = match.group(3)
                    match_case.append((file_name, line_number))
                else:
                    match_case.append((None, None))

        return match_case

    def extract(self, result_file_path, cwe_type):
        match_case = self.extract_file_and_line_from_txt(result_file_path, cwe_type)
        for file_name, line_number in match_case:
            file_path = self._get_path_from_url(file_name)
            file_path = self._normalize_path(file_path)
            if (file_name is not None) and (line_number is not None) and file_path in self.sources:
                function_name = self._get_function_by_line(file_path, int(line_number))
                if function_name.endswith("badSink") or function_name.endswith("bad") or function_name.endswith(
                        "badSource") or function_name.endswith("Bad"):
                    file_path = self.update_to_main_file(file_path)
                    file_path = self._normalize_path(file_path)
                    real_path = self._get_real_path(file_path)
                    extractor = SourceFunctionExtractor(real_path)
                    for cur_func in extractor.extract_functions_from_src():
                        cur_func_name: str = cur_func.name
                        if cur_func_name.endswith("_bad") or cur_func_name == "bad":
                            function_name = cur_func_name
                            break

                self.results[file_path].append(function_name)