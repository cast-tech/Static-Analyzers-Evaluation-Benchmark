import os.path
import re

from tools.run_tool import ToolRunner
from tools.support import run_cmd
from tools.build import cmake_build_stage, generate_bitcode

_SVF_DIR = os.environ.get("SVF_DIR", "/home/SVF-tools/SVF")
CLANG = os.path.join(_SVF_DIR, "llvm-18.1.0.obj", "bin")

os.environ["LLVM_COMPILER"] = "clang"
os.environ["LLVM_COMPILER_PATH"] = CLANG


def find_cwe_types(res_dir: str):
    match = re.search(r"CWE\d+", res_dir)

    if not match:
        return None
    cwe = match.group()
    cwe_map = {
        "CWE401": " -leak ",
        "CWE415": " -dfree "
    }

    return cwe_map.get(cwe, None)


def optimize_bitcode(bitcode_path: str):
    run_cmd(f"{CLANG}/opt -passes='mem2reg' -o {bitcode_path} {bitcode_path}", os.path.dirname(bitcode_path))


def run_analyze_stage(tool: str, res_dir: str):
    for file in os.listdir(res_dir):
        file_path = os.path.join(res_dir, file)
        if file.endswith(".bc") and os.path.isfile(file_path):
            optimize_bitcode(file_path)
            flags = find_cwe_types(file_path)
            result_file = os.path.splitext(file_path)[0] + ".svf.txt"
            command = f"{tool} {flags} {file_path} > {result_file} 2>&1 "
            print(f"Analyzing {file_path}")
            run_cmd(command, res_dir)


class SvfRunner(ToolRunner):
    DEFAULT_PATH = "/home/SVF-tools/SVF/Release-build/bin/saber"
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        cmake_build_stage("wllvm", "wllvm++", src_dir, res_dir, language)
        generate_bitcode(res_dir)
        run_analyze_stage(self.tool_path, res_dir)
