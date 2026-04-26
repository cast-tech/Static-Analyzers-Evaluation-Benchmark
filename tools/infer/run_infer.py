import os.path

from tools.run_tool import ToolRunner
from tools.base import Build, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd
from tools.build import MAKE_CMD, get_compiler, get_source_files


class InferRunner(ToolRunner):
    DEFAULT_PATH = os.path.join("tools", "infer", "bin", "infer")
    SUPPORTED_CWE_TYPES = ["memory_leak", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        if build == Build.CONF.value:
            run_cmd([self.tool_path, "compile", "-o", "result", "--", os.path.join(src_dir, "configure")], res_dir)
        if build == Build.CMAKE.value:
            run_cmd([self.tool_path, "compile", "-o", "result", "--", "cmake",
                     CMAKE_ARG_FOR_LANGUAGE[language].strip(), "-DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF" , src_dir], res_dir)

        build_cmd = MAKE_CMD
        if build == Build.FILES.value:
            c_files = get_source_files(src_dir, language)
            if not c_files:
                return
            build_cmd = get_compiler(language) + " " + c_files

        run_cmd(self.tool_path + " run --report-force-relative-path --sarif --pulse-only -o result -- " + build_cmd, res_dir)