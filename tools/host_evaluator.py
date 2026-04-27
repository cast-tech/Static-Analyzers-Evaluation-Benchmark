import os.path
import sys

PATH_TO_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(PATH_TO_SRC)

from tools.base import Test
from tools.support import set_clang_lib
from tools.run_tool import ToolRunner


def evaluate_tool(tool_name: str, tool_result_dir: str, test: Test, lib_clang_path: str):
    """Run evaluation (TPR/FPR) for a tool on the host after Docker execution completes.

    Reads raw tool output from tool_result_dir, computes metrics, and writes
    <tool>_rates.json and <tool>_classified_results.json next to tool_result_dir.
    """
    set_clang_lib(lib_clang_path)

    # Instantiate with a dummy tool_path — execute() is never called here,
    # only rate_tool() which does not use the binary.
    dummy_tool_path = ""
    tool_runner = ToolRunner.load_tool_runner(tool_name, dummy_tool_path,
                                              tool_result_dir, test)
    tool_runner.rate_tool()
