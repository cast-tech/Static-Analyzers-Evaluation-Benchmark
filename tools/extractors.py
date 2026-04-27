from urllib.parse import urlparse
import clang.cindex as cl
import importlib
import pathlib
import os.path
import json
import sys

from .base import Languages
from .support import get_files_from_dir_with_patterns


class SrcFunc:
    def __init__(self, name, start_line, end_line):
        self.name = name
        self.start_line = start_line
        self.end_line = end_line


class SourceFunctionExtractor:
    def __init__(self, path_to):
        self._src_path = path_to
        self._functions = []

        index = cl.Index.create()
        self._tu = index.parse(self._src_path)

    def _extract_functions(self, node):
        if (node.kind == cl.CursorKind.FUNCTION_DECL and node.is_definition()) or (
                node.kind == cl.CursorKind.CONSTRUCTOR and node.is_definition()):

            if node.extent.start.file.name == self._src_path:
                src_func = SrcFunc(node.spelling, node.extent.start.line, node.extent.end.line)
                self._functions.append(src_func)
        else:
            for child in node.get_children():
                self._extract_functions(child)

    def extract_functions_from_src(self):
        self._extract_functions(self._tu.cursor)
        return self._functions


class FunctionExtractor:
    def __init__(self, src_dir, result_dir, tool_name, cwe_type, language):
        self.tool = tool_name
        self.invalid_json = []
        self.sources, self.results = {}, {}
        self.language = language
        self._real_paths = {}
        self._extract_source_functions(src_dir, language)
        self._extract_result_functions(result_dir, cwe_type)
        self._keep_source_function_names_only()
        print(f"Invalid json count in {cwe_type} for {language} language is {len(self.invalid_json)}")


    def _keep_source_function_names_only(self):
        tmp = {}
        for src, src_func_list in self.sources.items():
            tmp[src] = [src_func.name for src_func in src_func_list]

        self.sources = tmp

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Return the portion of path from 'test_suites/' onward so that
        host paths and container paths compare equal."""
        marker = "test_suites" + os.sep
        idx = path.find(marker)
        return path[idx:] if idx != -1 else path

    def _extract_source_functions(self, src_dir, language):
        patterns = []
        if language == Languages.C.value:
            patterns = ["**/*.c", "**/*.h"]
        elif language == Languages.CPP.value:
            patterns = ["**/*.cpp", "**/*.hpp", "**/*.h"]
        src_files = get_files_from_dir_with_patterns(src_dir, patterns)
        for src in src_files:
            extractor = SourceFunctionExtractor(src)
            key = self._normalize_path(src)
            self._real_paths[key] = src
            self.sources[key] = extractor.extract_functions_from_src()
            self.results[key] = []

    def _get_real_path(self, normalized_path: str) -> str:
        """Resolve a normalized (test_suites/...) path back to the real host path.

        Falls back to basename matching so paths rewritten by
        update_to_main_file() still resolve even when their exact key was
        never seen on disk."""
        if normalized_path in self._real_paths:
            return self._real_paths[normalized_path]
        basename = os.path.basename(normalized_path)
        for key, real in self._real_paths.items():
            if os.path.basename(key) == basename:
                return real
        return normalized_path

    def extract(self, result_file_path, cwe_type):
        pass  # Override this on your tool extractor

    # Collects all .sarif files recursively by default. Override this if something else is needed
    def collect_result_files(self, result_dir):
        print("collect_result_files, result dir is ", result_dir)
        return get_files_from_dir_with_patterns(result_dir, ["**/*.sarif"])

    def _extract_result_functions(self, result_dir, cwe_type):
        print("Extracting result functions from " + result_dir)
        res_files = self.collect_result_files(result_dir)
        for res_file in res_files:
            self.extract(res_file, cwe_type)

    @staticmethod
    def load_tool_extractor(src_dir, result_dir, tool_name, cwe_type, language):
        try:
            module_name = f"tools.{tool_name}.extract_{tool_name}"  # Example: tools.infer.extract_infer
            class_name = (tool_name.replace("_", " ").  # Example: ml_hunter → MlHunterExtractor
                          title().replace(" ", "") + "Extractor")
            print(f"Importing class {class_name} from module {module_name}")
            module = importlib.import_module(module_name)
            return getattr(module, class_name)(src_dir, result_dir, tool_name, cwe_type, language)
        except ModuleNotFoundError:
            sys.exit(f"Critical error: Could not import. Please check if provided module and class are set correctly.")

    @staticmethod
    def update_to_main_file(file_path):
        name_without_extension, extension = os.path.splitext(file_path)
        for suffix in ["_bad", "_goodG2B", "_goodB2G"]:
            if name_without_extension.endswith(suffix):
                # Preserve the separator consumed with the suffix so e.g.
                # 'xxx_bad' → 'xxx_a' (Juliet convention), not 'xxxa'.
                name_without_extension = name_without_extension[: -len(suffix)] + "a"
                break
        else:
            if name_without_extension and name_without_extension[-1].isalpha():
                name_without_extension = name_without_extension[:-1] + "a"
        return name_without_extension + extension

    def get_source_file_from_function(self, function_name: str) -> str:
        prefix = function_name.replace("_bad", "").replace("_good", "")
        for src, funcs in self.sources.items():
            if os.path.basename(src).startswith(prefix):
                for func in funcs:
                    if func.name == function_name:
                        return src
        return ""

    def _get_function_by_line(self, file_path, line):
        if file_path in self.sources:
            functions = self.sources[file_path]
            for function in functions:
                if function.start_line <= line <= function.end_line:
                    return function.name

        return None

    @staticmethod
    def _get_function_name_from_msg(message):
        name = None
        if message.startswith("Calling"):
            function_name = message.split()[-1]
            name = FunctionExtractor._remove_single_quotes_from_name(function_name)

        return name

    @staticmethod
    def _remove_single_quotes_from_name(name):
        res_name = name
        if res_name.startswith("'"):
            res_name = res_name[1:]
            if res_name.endswith("'"):
                res_name = res_name[:-1]

        return res_name

    @staticmethod
    def _reg_uri_to_real(path_to_res, uri_path):
        tmp = pathlib.Path(uri_path)
        reg_path_from_res = os.path.join(os.pardir, os.pardir, os.pardir, pathlib.Path(*tmp.parts[1:]))
        path_to = os.path.join(path_to_res, reg_path_from_res)
        return os.path.realpath(path_to)

    def _get_path_from_url(self, url_path) -> str:
        parsed_path = urlparse(url_path).path
        absolute_path = os.path.abspath(parsed_path)
        return self._normalize_path(absolute_path)


class SARIFExtractor(FunctionExtractor):
    """Intermediate base class for extractors that parse SARIF output files.

    Subclasses must:
    - Set RULE_IDS = {cwe_type: [rule_id, ...]}
    - Implement _process_result(result_file_path, result, cwe_type)
    - Optionally set MESSAGE_FILTERED_RULES and CWE_MESSAGES for message-prefix filtering
    - Optionally override _is_result_for_cwe() for custom filtering logic
    """
    RULE_IDS: dict = {}
    CWE_MESSAGES: dict = {}
    MESSAGE_FILTERED_RULES: set = set()

    def _is_result_for_cwe(self, result, cwe_type) -> bool:
        if result.get("ruleId") not in self.RULE_IDS.get(cwe_type, []):
            return False
        if result["ruleId"] in self.MESSAGE_FILTERED_RULES:
            if not result["message"]["text"].startswith(self.CWE_MESSAGES.get(cwe_type, "")):
                return False
        return True

    def extract(self, result_file_path, cwe_type):
        with open(result_file_path, 'r') as res_file:
            result_file = json.load(res_file)
        for run in result_file.get("runs", []):
            for res in run.get("results", []):
                if not self._is_result_for_cwe(res, cwe_type):
                    continue
                self._process_result(result_file_path, res, cwe_type)

    def _process_result(self, result_file_path, result, cwe_type):
        pass  # Override in subclass
