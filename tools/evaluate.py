import argparse
import sys
import os

from .base import discover_tools, CweTypes, Languages
from .classifier import ResultClassifier, ResultPreserver
from .extractors import FunctionExtractor


def parse_args(arg_list):
    tools = discover_tools()
    cwe_types = [cwe.value for cwe in CweTypes]

    parser = argparse.ArgumentParser(description='Script for evaluating static analysis tool accuracy')
    parser.add_argument("--src-dir", dest="src_dir", required=True,
                        help="Path to sources directory")
    parser.add_argument("--result-dir", dest="result_dir", required=True,
                        help="Path to directory containing static analysis tool results")
    parser.add_argument("--tool", dest="tool", required=True,
                        help="Analysis tool name which results must be evaluated."
                             " Supported tools are: " + str(tools))
    parser.add_argument("--cwe-type", dest="cwe_type", required=True,
                        help="CWE type of the source. Supported CWE types are: " + str(cwe_types))
    parser.add_argument("--lib-clang", dest="lib_clang",
                            help="Path to clang library", default="", required=False)
    parser.add_argument("--c-only", dest="c_only",
                        help="Enable to evaluate results only on C sources",
                        action="store_true", default=False)
    parser.add_argument("--cpp-only", dest="cpp_only",
                        help="Enable to evaluate results only on CPP sources",
                        action="store_true", default=False)

    args = parser.parse_args(arg_list)
    check_args(parser, args, tools, cwe_types)
    return args


def check_args(parser, args, tools, cwe_types):
    if args.src_dir is not None and not os.path.isdir(args.src_dir):
        parser.error(f"Given path is not a directory: {args.src_dir}")
    if args.result_dir is not None and not os.path.isdir(args.result_dir):
        parser.error(f"Given path is not a directory: {args.result_dir}")
    if args.tool not in tools:
        parser.error(f"Given tool name is not supported: {args.tool}")
    if args.cwe_type not in cwe_types:
        parser.error(f"Given CWE type is not supported: {args.cwe_type}")
    if args.lib_clang and not os.path.exists(args.lib_clang):
        parser.error(f"Given library file doesn't exist: {args.lib_clang}")
    if args.c_only and args.cpp_only:
        parser.error(f"Evaluating results on multiple languages isn't allowed!")
    if not args.c_only and not args.cpp_only:
        parser.error(f"One language must be set!")


class Evaluate:
    def __init__(self, classifier: ResultClassifier):
        duplicate_filtered_tp = self.filter_duplicates(classifier.tp_results)
        duplicate_filtered_fp = self.filter_duplicates(classifier.fp_results)

        self._tp_duplicate_count = (self.get_item_count(classifier.tp_results) -
                                    self.get_item_count(duplicate_filtered_tp))
        self._fp_duplicate_count = (self.get_item_count(classifier.fp_results) -
                                    self.get_item_count(duplicate_filtered_fp))

        self._tp_count = self.get_item_count(duplicate_filtered_tp)
        self._fp_count = self.get_item_count(duplicate_filtered_fp)
        self._tn_count = self.get_item_count(classifier.tn_results)
        self._fn_count = self.get_item_count(classifier.fn_results)

        self.validate_evaluation(classifier)

        self.print_false_negatives(classifier.fn_results)
        self.print_false_positives(classifier.fp_results)

    def validate_evaluation(self, classifier: ResultClassifier):
        if self._tn_count != self.get_item_count(classifier.good_functions) - self._fp_count:
            print("Warning! Invalid count of true negatives has been calculated. Consider checking them manually")
        if self._fn_count != self.get_item_count(classifier.bad_functions) - self._tp_count:
            print("Warning! Invalid count of false negatives has been calculated. Consider checking them manually")

    @staticmethod
    def get_item_count(source: dict):
        return sum(len(value) for value in source.values())

    @staticmethod
    def filter_duplicates(source: dict) -> dict:
        filtered_result = dict()

        for src, function_list in source.items():
            filtered_result[src] = []
            for function in function_list:
                if function in filtered_result[src]:
                    print(f"Function '{function}' has been filtered in file: {src}")
                    continue
                filtered_result[src].append(function)

        return filtered_result

    @staticmethod
    def print_false_negatives(false_negative_results: dict):
        for src, false_negative_function_list in false_negative_results.items():
            for false_negative_function in false_negative_function_list:
                print(f"False negative in '{false_negative_function}'. Source file: {src}")

    @staticmethod
    def print_false_positives(false_positive_results: dict):
        for src, false_positive_function_list in false_positive_results.items():
            for false_positive_function in false_positive_function_list:
                print(f"False positive in '{false_positive_function}'. Source file: {src}")

    def true_positive_duplicate_count(self):
        return self._tp_duplicate_count

    def false_positive_duplicate_count(self):
        return self._fp_duplicate_count

    def true_positive_count(self):
        return self._tp_count

    def false_positive_count(self):
        return self._fp_count

    def true_negative_count(self):
        return self._tn_count

    def false_negative_count(self):
        return self._fn_count

    def true_positive_rate(self):
        return 100 * self._tp_count / (self._tp_count + self._fn_count)

    def false_positive_rate(self):
        return 100 * self._fp_count / (self._fp_count + self._tn_count)

    def true_negative_rate(self):
        return 100 * self._tn_count / (self._tn_count + self._fp_count)

    def false_negative_rate(self):
        return 100 * self._fn_count / (self._fn_count + self._tp_count)


def evaluate(arg_list):
    args = parse_args(arg_list)

    language = (Languages.C.value if args.c_only else "")
    language = (Languages.CPP.value if args.cpp_only else language)
    extractor = FunctionExtractor.load_tool_extractor(args.src_dir, args.result_dir, args.tool, args.cwe_type, language)
    classifier = ResultClassifier(extractor.sources, extractor.results, language)

    classified_results_path = os.path.join(os.path.dirname(args.result_dir), args.tool + "_classified_results.json")
    ResultPreserver(classifier, str(classified_results_path), args.cwe_type, language)

    return Evaluate(classifier)


if __name__ == '__main__':
    rates = evaluate(sys.argv[1:])
    print(f"TPC = {rates.true_positive_count()}")
    print(f"TNC = {rates.true_negative_count()}")
    print(f"FPC = {rates.false_positive_count()}")
    print(f"FNC = {rates.false_negative_count()}")
    print(f"TPR = {rates.true_positive_rate()}")
    print(f"TNR = {rates.true_negative_rate()}")
    print(f"FPR = {rates.false_positive_rate()}")
    print(f"FNR = {rates.false_negative_rate()}")
