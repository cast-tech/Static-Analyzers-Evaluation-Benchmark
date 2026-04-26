import os.path
from pathlib import Path

from tools.base import Languages
from tools.run_tool import ToolRunner
from tools.support import run_cmd_cbmc


def extract_base_name(file_name):
    name_without_ext = file_name.rsplit(".", 1)[0]
    name_without_ext = os.path.basename(name_without_ext)
    parts = name_without_ext.rsplit("_", 1)
    if len(parts) > 1 and (len(parts[1]) == 1 or not parts[1][0].isdigit()):
        return parts[0]
    return name_without_ext

def get_all_files(directory):
    return [str(file) for file in Path(directory).rglob('*') if file.is_file()]

def iterate_over_all_files(cbmc: str, build: str, source_dir: str, result_dir: str, failed_files: list, language: str):
    files = get_all_files(source_dir)
    for src in files:
        if (src.endswith(".c") and language == Languages.C.value) or (
                src.endswith(".cpp") and language == Languages.CPP.value):
            pattern = os.path.splitext(src)[1]
            name_without_extension = extract_base_name(src)
            symbol_a = "*"
            if name_without_extension[-1].isalpha():
                name_without_extension = name_without_extension[:-1]
            full_path_src = os.path.join(os.path.dirname(src), name_without_extension)
            testcase_support_dir = os.path.join(source_dir, os.pardir, os.pardir, "testcasesupport/")
            src_file = full_path_src + symbol_a + pattern

            cmd = (cbmc + " -DOMITGOOD -DINCLUDEMAIN=ON "
                            "-I" + testcase_support_dir +
                   " --no-standard-checks --pointer-check --memory-leak-check --trace --json-ui --compact-trace " + src_file + " > " + os.path.join(
                        result_dir,
                        name_without_extension) + "_bad_report.json")
            run_cmd_cbmc(name_without_extension, failed_files, cmd)
            cmd = (cbmc + " -DOMITBAD -DINCLUDEMAIN=ON "
                            "-I" + testcase_support_dir +
                   " --no-standard-checks --pointer-check --memory-leak-check --trace --json-ui --compact-trace " + src_file + " > " + os.path.join(
                        result_dir,
                        name_without_extension) + "_good_report.json")
            run_cmd_cbmc(name_without_extension, failed_files, cmd)

def run(cbmc: str, build: str, source_dir: str, result_dir: str, language: str):
    failed_files = []
    iterate_over_all_files(cbmc, build, source_dir, result_dir, failed_files, language)

    failed_log = os.path.join(result_dir, "failed_files.txt")
    with open(failed_log, "w") as f:
        f.write("\n".join(failed_files))
    print(f"Wrote {len(failed_files)} failed files to {failed_log}")

class CbmcRunner(ToolRunner):
    DEFAULT_PATH = "/usr/bin/cbmc"
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]
    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        run(self.tool_path, build, src_dir, res_dir, language)
