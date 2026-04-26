import os.path

from tools.run_tool import ToolRunner
from tools.base import Build, Languages, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd, get_files_from_dir_with_patterns

def get_parent_dir(path: str) -> str:
    return os.path.dirname(os.path.realpath(path))

def analyse(tool_path: str, src_dir: str, res_dir: str, build: str, language: str):
    tool_parent_dir = get_parent_dir(tool_path)
    if build == Build.CONF.value:
        run_cmd([os.path.join(src_dir, "configure")], res_dir)
    if build == Build.CMAKE.value:
        run_cmd(["cmake", f"-DCMAKE_C_COMPILER={tool_parent_dir}/cgcc",
                 CMAKE_ARG_FOR_LANGUAGE[language].strip(), "-DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF", src_dir], res_dir)
    analyse_cmd = f"make CHECK=\"{tool_path} --full=path\" CC={tool_parent_dir}/cgcc | tee smatch_out.sm"
    if build == Build.FILES.value:
        c_files = " ".join(get_files_from_dir_with_patterns(src_dir, ["*.c"]))

        if not c_files:
            return
        analyse_cmd = tool_path + " " + c_files + "| tee smatch_out.sm"

    run_cmd(analyse_cmd, res_dir)


class SmatchRunner(ToolRunner):
    DEFAULT_PATH = os.path.join("tools", "smatch", "smatch", "smatch")
    SUPPORTED_CWE_TYPES = ["double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        if build == Build.CMAKE or build == Build.CONF.value:
            print(f"Invalid test suite configuration: {build}. Skipping analysis for the given test suite.")
            print("Hint: Build and configure types are not supported by this tool")
            print("The only options it supports: raw files or preprocessed files")
            return

        analyse(self.tool_path, src_dir, res_dir, build, language)
