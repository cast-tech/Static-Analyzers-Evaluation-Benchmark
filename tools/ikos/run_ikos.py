import os.path
from os.path import realpath
from pathlib import Path

from tools.run_tool import ToolRunner
from tools.base import Build, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd
from tools.build import MAKE_CMD, get_compiler, get_source_files


def ikos_report(ikos: str, result_dir: str):
    for file in Path(result_dir).rglob("*.db"):
        report_cmd = ikos + "-report" + " -f sarif --status-filter error " + realpath(
            file) + " > " + result_dir + "/" + os.path.basename(file) + ".sarif"
        run_cmd(report_cmd, result_dir)


class IkosRunner(ToolRunner):
    DEFAULT_PATH = os.path.join("tools", "ikos", "install", "bin", "ikos")
    SUPPORTED_CWE_TYPES = ["double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        if build == Build.CONF.value:
            run_cmd([self.tool_path + "-scan", os.path.join(src_dir, "configure")], res_dir)
        if build == Build.CMAKE.value:
            run_cmd([self.tool_path + "-scan", "cmake", CMAKE_ARG_FOR_LANGUAGE[language].strip(), "-DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF", src_dir], res_dir)

        build_cmd = MAKE_CMD
        if build == Build.FILES.value:
            c_files = get_source_files(src_dir, language)
            if not c_files:
                return
            build_cmd = get_compiler(language) + " " + c_files

        run_cmd(self.tool_path + "-scan " + build_cmd, res_dir)
        ikos_report(self.tool_path, res_dir)
