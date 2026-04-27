import json
import os

from .base import Languages, Test, Source
from .evaluate import Evaluate, evaluate

class Rate:
    def __init__(self, test_name: str, cwe_type: str, language: str, rates: Evaluate):
        self.test_name = test_name
        self.cwe_type = cwe_type
        self.language = language
        self.true_positive_duplicate_count = rates.true_positive_duplicate_count()
        self.false_positive_duplicate_count = rates.false_positive_duplicate_count()
        self.true_positive_count = rates.true_positive_count()
        self.false_positive_count = rates.false_positive_count()
        self.true_negative_count = rates.true_negative_count()
        self.false_negative_count = rates.false_negative_count()
        self.true_positive_rate = rates.true_positive_rate()
        self.false_positive_rate = rates.false_positive_rate()
        self.true_negative_rate = rates.true_negative_rate()
        self.false_negative_rate = rates.false_negative_rate()


class ToolRates:
    def __init__(self, name: str):
        self.name = name
        self.rates = []

    def add(self, rates_list: list):
        for rate_ in rates_list:
            self.rates.append(rate_)

    def append_to_json(self, file_json: str):
        with open(file_json, "a") as file_:
            file_.write(json.dumps(self, default=lambda obj: obj.__dict__, indent=4))
            file_.write("\n")


def get_rate(name: str, source_path: str, result_path: str, tool: str, cwe_type: str, language: str) -> Rate:
    evaluate_args = ["--src-dir", source_path,
                     "--result-dir", result_path,
                     "--cwe-type", cwe_type,
                     "--tool", tool,
                     "--lib-clang", ""]
    if language == Languages.C.value:
        evaluate_args.append("--c-only")
    elif language == Languages.CPP.value:
        evaluate_args.append("--cpp-only")

    rates = evaluate(evaluate_args)

    return Rate(name, cwe_type, language, rates)


def get_rates(source: Source, result_path: str, tool: str, language: str) -> list:
    if not source.verbose:
        source_result_path = os.path.join(result_path, source.reg_path)
        return [
            get_rate(source.name, source.path, source_result_path, tool, source.cwe_type, language)
        ]

    rates = []
    for subdir in os.listdir(source.path):
        sub_source_name = os.path.join(source.name, subdir)
        sub_source_path = os.path.join(source.path, subdir)
        sub_source_result_path = os.path.join(result_path, source.reg_path, subdir)

        rates.append(
            get_rate(sub_source_name, sub_source_path, sub_source_result_path, tool, source.cwe_type, language)
        )

    return rates


def rate(tool: str, test: Test, result_path: str, language: str):
    tool_rates = ToolRates(tool)
    for source in test.sources:
        print(f"Calculating analysis rates on test suite: {source.name}, CWE type: {source.cwe_type}\n"
              f"Tool: {tool}, language: {language}\n")
        tool_rates.add(get_rates(source, result_path, tool, language))

    return tool_rates.rates
