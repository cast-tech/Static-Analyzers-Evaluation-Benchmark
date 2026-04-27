from abc import ABC, abstractmethod
from os.path import realpath
import importlib
import os.path
import sys

PATH_TO_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH_TO_SRC)

from tools.base import Build, Test
from tools.support import create_dir, get_result_path, collect_sources


class ToolRunner(ABC):
    DEFAULT_PATH = None
    SUPPORTED_CWE_TYPES = []
    SUPPORTED_LANGUAGES = []

    def __init__(self, tool_name: str, tool_path: str, result_dir: str, test: Test):
        self.tool_name = tool_name
        self.tool_path = tool_path
        self._result_dir = result_dir
        self._test = test

    @abstractmethod
    def execute(self, src_dir: str, res_dir: str, build: Build, language: str):
        pass

    def _filter_sources(self, language):
        sources_to_analyze = []
        for test_source in self._test.sources:
            if test_source.cwe_type not in self.SUPPORTED_CWE_TYPES:
                print(f"Skipping analysis of {test_source.name} test suite on tool: {self.tool_name}, "
                      f"for language {language}.\n"
                      f"CWE type {test_source.cwe_type} is not supported by tool.")
                continue
            if language not in test_source.languages:
                print(f"Skipping analysis of {test_source.name} test suite with CWE type {test_source.cwe_type} "
                      f"on tool: {self.tool_name}, for language {language}.\n"
                      f"Language {language} is not supported by the test suite.")
                continue
            sources_to_analyze.append(test_source)
        return sources_to_analyze

    def _execute_on(self, language):
        sources_to_analyze = self._filter_sources(language)
        for test_source in sources_to_analyze:
            for source in collect_sources(test_source):
                src_dir = realpath(source)
                res_dir = create_dir(realpath(get_result_path(self._result_dir, source, PATH_TO_SRC, language)))
                self.execute(src_dir, res_dir, test_source.build, language)

    def _rate_on(self, language):
        from tools.rate import rate
        sources_to_analyze = self._filter_sources(language)
        return rate(self.tool_name, Test(sources_to_analyze), self._result_dir, language)

    def execute_tool(self):
        for supported_language in self.SUPPORTED_LANGUAGES:
            self._execute_on(supported_language)

    def rate_tool(self):
        from tools.rate import ToolRates
        rates = ToolRates(self.tool_name)
        for supported_language in self.SUPPORTED_LANGUAGES:
            language_rate = self._rate_on(supported_language)
            rates.add(language_rate)

        path_to_rates = os.path.join(os.path.dirname(self._result_dir), self.tool_name + "_rates.json")
        rates.append_to_json(str(path_to_rates))

    @staticmethod
    def load_tool_runner(tool_name: str, tool_path: str, result_dir: str, test_obj: Test):
        try:
            module_name = f"tools.{tool_name}.run_{tool_name}"  # Example: tools.infer.run_infer
            class_name = (tool_name.replace("_", " ").  # Example: ml_hunter → MlHunterRunner
                          title().replace(" ", "") + "Runner")
            print(f"Importing class {class_name} from module {module_name}")
            module = importlib.import_module(module_name)
            return getattr(module, class_name)(tool_name, tool_path, result_dir, test_obj)
        except ModuleNotFoundError:
            sys.exit(f"Critical error: Could not import. Please check if provided module and class are set correctly.")
