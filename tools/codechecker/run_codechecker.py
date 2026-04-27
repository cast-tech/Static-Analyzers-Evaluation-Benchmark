import os.path

from tools.run_tool import ToolRunner
from tools.base import Build, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd
from tools.build import MAKE_CMD, get_compiler, get_source_files


checkers_to_enable = [
    "unix.Malloc",
    "cplusplus.NewDelete",
    "cplusplus.NewDeleteLeaks",
    "cplusplus.InnerPointer",
    "cplusplus.Move"
]

def construct_arguments() -> str:
    arguments = list()

    arguments.extend(["analyze", "compile_commands.json", "--analyzers", "clangsa", "--output", "results", "--ctu"])

    for enable_checker in checkers_to_enable:
        arguments.extend(["--enable", enable_checker])

    return " ".join(arguments) + " "


class CodecheckerRunner(ToolRunner):
    DEFAULT_PATH = "/usr/local/bin/CodeChecker"
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        command_prefix = self.tool_path + " " + construct_arguments()

        if build == Build.CONF.value:
            run_cmd(os.path.join(src_dir, "configure"), res_dir)
        if build == Build.CMAKE.value:
            run_cmd("cmake " + CMAKE_ARG_FOR_LANGUAGE[language] + " -DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF " + src_dir, res_dir)

        build_cmd = self.tool_path + f" log -b \"{MAKE_CMD}\" -o compile_commands.json"
        if build == Build.FILES.value:
            c_files = get_source_files(src_dir, language)
            if not c_files:
                return
            build_cmd = self.tool_path + " log -b \"" + get_compiler(language) + " " + c_files + "\" -o compile_commands.json"
        run_cmd(build_cmd, res_dir)
        run_cmd(command_prefix, res_dir)
        report_extract_cmd = self.tool_path + " parse results --export sarif  --output results/results.sarif || [ $? -eq 2 ]"
        run_cmd(report_extract_cmd, res_dir)
