import argparse
import os.path
import sys

PATH_TO_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH_TO_SRC)

from tools.base import Test, discover_tools
from tools.support import get_tool_default_path
from tools.run_tool import ToolRunner


def parse_args(arg_list: list):
    test_config_default = os.path.join(PATH_TO_SRC, "test_suite_config.json")

    arg_parser = argparse.ArgumentParser(description="Runs the static analysis tool inside Docker "
                                                     "and writes raw output to the result directory. "
                                                     "Evaluation (TPR/FPR) is performed on the host.",
                                         usage="PATH_TO_PYTHON_BIN PATH_TO_SCRIPT OPTIONS")
    arg_parser.add_argument("--config", dest="config_path",
                            help="JSON file path containing the test suite configuration.",
                            default=test_config_default)
    arg_parser.add_argument("--result", dest="result_dir",
                            help="Directory path to store results.", required=True)
    arg_parser.add_argument("--tool-path", dest="tool_path",
                            help="Path of the already installed tool binary")
    arg_parser.add_argument("--tool-name", dest="tool_name",
                            help="Name of the static analysis tool", required=True)

    args = arg_parser.parse_args(arg_list)

    tool_default_path = get_tool_default_path(PATH_TO_SRC, args.tool_name)
    if not args.tool_path:
        args.tool_path = tool_default_path

    check_args(arg_parser, args)

    test = Test.load_from_json(args.config_path, PATH_TO_SRC)
    return args, test


def check_args(arg_parser: argparse.ArgumentParser, args: argparse.Namespace):
    if not os.path.exists(args.config_path):
        arg_parser.error(f"Given config file path doesn't exist: {args.config_path}")
    if args.tool_name not in discover_tools():
        arg_parser.error(f"Given tool name isn't recognized: {args.tool_name}")


def run_tool(arg_list: list):
    args, test = parse_args(arg_list)

    tool_runner = ToolRunner.load_tool_runner(args.tool_name, args.tool_path,
                                              args.result_dir, test)
    tool_runner.execute_tool()

    return args.result_dir


if __name__ == '__main__':
    try:
        result_dir = run_tool(sys.argv[1:])
        print("Result directory: ", result_dir)
    except Exception as err:
        print(str(err))
        exit(1)
