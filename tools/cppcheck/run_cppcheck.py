import os.path

from tools.run_tool import ToolRunner
from tools.base import Build, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd
from tools.build import MAKE_CMD, get_compiler, get_source_files


def construct_arguments():
    arguments = list()
    arguments.extend(["--project=compile_commands.json", "--library=posix", "--enable=all",
                      "--inconclusive", "--check-level=exhaustive", "--output-format=sarif"])
    arguments.extend(["2> report.sarif"])

    return " ".join(arguments) + " "


class CppcheckRunner(ToolRunner):
    DEFAULT_PATH = "/usr/local/bin/cppcheck"
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        command_prefix = self.tool_path + " " + construct_arguments()

        if build == Build.CONF.value:
            run_cmd(os.path.join(src_dir, "configure"), res_dir)
        if build == Build.CMAKE.value:
            run_cmd("cmake " + CMAKE_ARG_FOR_LANGUAGE[language] + " -DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF " + src_dir, res_dir)

        postfix = "bear -- " + MAKE_CMD
        if build == Build.FILES.value:
            c_files = get_source_files(src_dir, language)
            if not c_files:
                return
            postfix = "bear --" + get_compiler(language) + " " + c_files

        run_cmd(postfix, res_dir)
        run_cmd(command_prefix, res_dir)
