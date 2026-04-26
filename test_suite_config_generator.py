from os.path import dirname
import argparse
import sys
import re
import os

from tools.base import Test, Source, Build, CweTypes, Languages

PATH_TO_SRC = dirname(os.path.realpath(os.path.abspath(__file__)))
CWE_401_PATH = os.path.join("test_suites", "CWE_401_memory_leak")
CWE_415_PATH = os.path.join("test_suites", "CWE_415_double_free")
CWE_416_PATH = os.path.join("test_suites", "CWE_416_use_after_free")


def construct_test_sources(args_verbose) -> dict[str, Source]:
    return {
        "memory_leak_main_tests_config": Source("main_tests_config", CweTypes.MEMORY_LEAK.value,
                                                [Languages.C.value],
                                                os.path.join(CWE_401_PATH, "main_tests_config"),
                                                PATH_TO_SRC, verbose=args_verbose),
        "memory_leak_main_tests": Source("main_tests", CweTypes.MEMORY_LEAK.value,
                                         [Languages.C.value],
                                         os.path.join(CWE_401_PATH, "main_tests"), PATH_TO_SRC,
                                         verbose=args_verbose),
        "memory_leak_real_tests": Source("real_tests", CweTypes.MEMORY_LEAK.value,
                                         [Languages.C.value],
                                         os.path.join(CWE_401_PATH, "real_tests"), PATH_TO_SRC,
                                         verbose=args_verbose),
        "memory_leak_main_tests_with_headers": Source("main_tests_with_headers", CweTypes.MEMORY_LEAK.value,
                                                      [Languages.C.value],
                                                      os.path.join(CWE_401_PATH, "main_tests_with_headers"),
                                                      PATH_TO_SRC, verbose=args_verbose),
        "memory_leak_main_tests_multy_src": Source("main_tests_multy_src", CweTypes.MEMORY_LEAK.value,
                                                   [Languages.C.value],
                                                   os.path.join(CWE_401_PATH, "main_tests_multy_src"), PATH_TO_SRC,
                                                   verbose=args_verbose),
        "memory_leak_cmake_main_tests": Source("cmake_main_tests", CweTypes.MEMORY_LEAK.value,
                                               [Languages.C.value],
                                               os.path.join(CWE_401_PATH, "cmake_main_tests"),
                                               PATH_TO_SRC, build_type=str(Build.CMAKE.value)),
        "memory_leak_configure_build": Source("configure_build", CweTypes.MEMORY_LEAK.value,
                                              [Languages.C.value],
                                              os.path.join(CWE_401_PATH, "configure_build"),
                                              PATH_TO_SRC, build_type=str(Build.CONF.value)),

        "memory_leak_juliet_reduced": Source("juliet_reduced", CweTypes.MEMORY_LEAK.value,
                                            [Languages.C.value, Languages.CPP.value],
                                            os.path.join(CWE_401_PATH, "juliet_reduced", "testcases"),
                                            PATH_TO_SRC, build_type=str(Build.CMAKE.value)),
        "memory_leak_juliet_tests": Source("juliet_tests", CweTypes.MEMORY_LEAK.value,
                                           [Languages.C.value, Languages.CPP.value],
                                           os.path.join(CWE_401_PATH, "juliet_tests", "testcases"),
                                           PATH_TO_SRC, build_type=str(Build.CMAKE.value)),

        "double_free_juliet_reduced": Source("juliet_reduced", CweTypes.DOUBLE_FREE.value,
                                             [Languages.C.value, Languages.CPP.value],
                                             os.path.join(CWE_415_PATH, "juliet_reduced", "testcases"),
                                             PATH_TO_SRC, build_type=str(Build.CMAKE.value)),
        "double_free_juliet_tests": Source("juliet_tests", CweTypes.DOUBLE_FREE.value,
                                           [Languages.C.value, Languages.CPP.value],
                                           os.path.join(CWE_415_PATH, "juliet_tests", "testcases"),
                                           PATH_TO_SRC, build_type=str(Build.CMAKE.value)),

        "use_after_free_juliet_reduced": Source("juliet_reduced", CweTypes.USE_AFTER_FREE.value,
                                                [Languages.C.value, Languages.CPP.value],
                                                os.path.join(CWE_416_PATH, "juliet_reduced", "testcases"),
                                                PATH_TO_SRC, build_type=str(Build.CMAKE.value)),
        "use_after_free_juliet_tests": Source("juliet_tests", CweTypes.USE_AFTER_FREE.value,
                                              [Languages.C.value, Languages.CPP.value],
                                              os.path.join(CWE_416_PATH, "juliet_tests", "testcases"),
                                              PATH_TO_SRC, build_type=str(Build.CMAKE.value)),
    }


def parse_args(arg_list: list) -> tuple[argparse.Namespace, list[Source]]:
    help_test_source_names = list(construct_test_sources("").keys())
    available_sources = "\n\t".join(help_test_source_names)

    arg_parser = argparse.ArgumentParser(description="This script generates a JSON file specifying test suites "
                                                     "to run and their configurations.",
                                         usage="PATH_TO_PYTHON_BIN PATH_TO_SCRIPT [--verbose] "
                                               "[--result <path>] <patterns>...\n\n"
                                               f"Available test sources:\n\t{available_sources}")
    arg_parser.add_argument("--verbose", dest="verbose",
                            help="Evaluate rates for each test case", action="store_true", default=False)
    arg_parser.add_argument("--result", dest="result_path",
                            help="The directory path to store the results",
                            default=os.path.join(PATH_TO_SRC, "test_suite_config.json"))
    arg_parser.add_argument("patterns", type=str, nargs='+',
                            help="Regular expression pattern(s) to match test source names")


    args = arg_parser.parse_args(arg_list)
    test_sources = construct_test_sources(args.verbose)

    matching_sources = [test_sources[name] for name in test_sources if any(re.search(pattern, name)
                                                                                for pattern in args.patterns)]
    check_args(arg_parser, args, matching_sources)
    return args, matching_sources


def check_args(arg_parser: argparse.ArgumentParser, args: argparse.Namespace, matching_sources: list):
    if not matching_sources:
        arg_parser.error("No test sources match the given pattern.")
    if not os.path.exists(args.result_path):
        arg_parser.error(f"Given result file path doesn't exist: {args.result_path}")


def main(arg_list: list):
    args, test_sources = parse_args(arg_list)

    test = Test(sources=test_sources)
    test.save_to_json(args.result_path)

    print("\nYou can check test suite configuration in:", args.result_path)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as err:
        print(str(err))
        exit(1)
