import os.path

from tools.run_tool import ToolRunner
from tools.support import run_cmd
from tools.build import cmake_build_stage, generate_bitcode

CLANG = "/klee/klee-3.1/external/llvm16/bin"

os.environ["LLVM_COMPILER"] = "clang"
os.environ["LLVM_COMPILER_PATH"] = CLANG


def run_analyze_stage(tool: str, res_dir: str):
    for file in os.listdir(res_dir):
        file_path = os.path.join(res_dir, file)
        if file.endswith(".bc") and os.path.isfile(file_path):
            flags = f""
            command = f"{tool} {flags} {file_path}"
            print(f"Analyzing {file_path}")
            run_cmd(command, res_dir)


class KleeRunner(ToolRunner):
    DEFAULT_PATH = "/klee/klee-3.1/build/bin/klee"
    SUPPORTED_CWE_TYPES = ["double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]
    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        cmake_build_stage("wllvm", "wllvm++", src_dir, res_dir, language)
        generate_bitcode(res_dir)
        run_analyze_stage(self.tool_path, res_dir)
