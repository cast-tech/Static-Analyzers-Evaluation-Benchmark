import os
import json
from enum import Enum


class FunctionTypes(Enum):
    GOOD = "good"
    BAD = "bad"
    NON_BAD = "non_bad"

C_GOOD_SUFFIX = "_good"
C_BAD_SUFFIX = "_bad"
CPP_GOOD_FUNCTION = "good"
CPP_BAD_FUNCTION = "bad"


class ResultClassifier:
    def __init__(self, sources: dict, results: dict, language: str):
        self._sources = sources
        self._results = results
        self.language = language
        self.good_functions = self._collect_good_functions()
        self.bad_functions = self._collect_bad_functions()

        self.tp_results, self.fp_results = self._collect_positive_results()
        self.tn_results, self.fn_results = self._collect_negative_results()

    def _collect_good_functions(self):
        good_functions = {}
        for src_file in self._sources:
            good_functions[src_file] = self._get_functions_with_type(
                [func for func in self._sources[src_file]], FunctionTypes.NON_BAD, self.language)

        return good_functions

    def _collect_bad_functions(self):
        bad_functions = {}
        for src_file in self._sources:
            bad_functions[src_file] = self._get_functions_with_type(
                [func for func in self._sources[src_file]], FunctionTypes.BAD, self.language)

        return bad_functions

    def _collect_positive_results(self):
        tp_results, fp_results = {}, {}

        for src, function_list in self._results.items():
            tp_results[src], fp_results[src] = [], []
            for function in function_list:
                if self._function_is_type(function, FunctionTypes.BAD, self.language):
                    tp_results[src].append(function)
                else:
                    fp_results[src].append(function)

        return tp_results, fp_results

    def _collect_negative_results(self):
        tn_results, fn_results = {}, {}

        for src, function_list in self._sources.items():
            tn_results[src], fn_results[src] = [], []
            for function in function_list:
                if self._function_is_type(function, FunctionTypes.BAD, self.language):
                    if not function in self.tp_results[src]:
                        fn_results[src].append(function)
                else:
                    if not function in self.fp_results[src]:
                        tn_results[src].append(function)

        return tn_results, fn_results

    @staticmethod
    def _get_functions_with_type(all_functions, function_type, language):
        functions = []
        for func_name in all_functions:
            if function_type == FunctionTypes.GOOD:
                if func_name.endswith(C_GOOD_SUFFIX) or func_name == CPP_GOOD_FUNCTION:
                    functions.append(func_name)
            elif function_type == FunctionTypes.BAD:
                if (func_name.endswith(C_BAD_SUFFIX) and language == "C") or (
                        func_name == CPP_BAD_FUNCTION and language == "CPP"):
                    functions.append(func_name)
            elif function_type == FunctionTypes.NON_BAD:
                if ((not func_name.endswith(C_BAD_SUFFIX)) and language == "C") or (
                        (not func_name == CPP_BAD_FUNCTION) and language == "CPP"):
                    functions.append(func_name)

        return functions

    @staticmethod
    def _function_is_type(function, function_type, language):
        if ResultClassifier._get_functions_with_type([function], function_type, language):
            return True
        return False


class ResultPreserver:
    def __init__(self, classifier: ResultClassifier, json_file_path: str, cwe_type: str, language: str):
        public_fields = self._get_public_fields(classifier)
        append_key = cwe_type + " " + language

        self._dump_fields_to_json_with_key(public_fields, json_file_path, append_key)

    @staticmethod
    def _dump_fields_to_json_with_key(fields: dict, json_file_path: str, append_key: str):
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r') as file:
                data = json.load(file)
        else:
            data = {}

        data[append_key] = fields
        with open(json_file_path, 'w') as file:
            json.dump(data, file, indent=4)

    @staticmethod
    def _get_public_fields(classifier: ResultClassifier):
        return {k: v for k, v in vars(classifier).items() if not k.startswith('_')}
