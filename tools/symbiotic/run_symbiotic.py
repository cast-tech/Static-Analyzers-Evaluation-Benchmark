import os.path
from pathlib import Path

from tools.run_tool import ToolRunner
from tools.support import run_cmd

def get_all_files(directory):
    return [str(file) for file in Path(directory).rglob('*') if file.is_file()]

def iterate_over_all_files(symbiotic: str, source_dir: str, result_dir: str, failed_files: list):
    files = get_all_files(source_dir)
    for src in files:
        if src.endswith(".c"):
            full_path = os.path.splitext(src)[0]
            name_without_extension = os.path.basename(full_path)

            if name_without_extension[-1].isalpha():
                name_without_extension = name_without_extension[:-1]
                full_path = full_path[:-1]
            full_path_src = os.path.join(source_dir, full_path)
            testcase_support_dir = os.path.join(source_dir, os.pardir, os.pardir, "testcasesupport/")
            cmd = ("CPPFLAGS=' -DOMITGOOD -DINCLUDEMAIN=ON "
                   "-I" + testcase_support_dir +
                   "' " + symbiotic + " --prp=memsafety --report=sv-comp " + full_path_src +
                   "*.c > " + os.path.join(result_dir,
                                           name_without_extension) + "_bad_report.txt")
            try:
                run_cmd(cmd)
            except RuntimeError:
                failed_files.append(full_path_src)
                print("REPORT IS NOT GENERATED!!!!!!!!!!!!!!!!")
            cmd = ("CPPFLAGS=' -DOMITBAD -DINCLUDEMAIN=ON "
                   "-I" + testcase_support_dir +
                   "' " + symbiotic + " --prp=memsafety --report=sv-comp " + full_path_src +
                   "*.c > " + os.path.join(result_dir,
                                           name_without_extension) + "_good_report.txt")
            try:
                run_cmd(cmd)
            except RuntimeError:
                failed_files.append(full_path_src)


class SymbioticRunner(ToolRunner):
    DEFAULT_PATH = os.path.join("tools", "symbiotic", "symbiotic", "install", "bin", "symbiotic")
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free"]
    SUPPORTED_LANGUAGES = ["C"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        failed_files = []
        iterate_over_all_files(self.tool_path, src_dir, res_dir, failed_files)
        print("Files that failed:", failed_files)
        print("Count of files that failed:", len(failed_files))
