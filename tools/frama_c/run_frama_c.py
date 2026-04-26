import os.path
from os.path import realpath, dirname
from pathlib import Path

from tools.run_tool import ToolRunner
from tools.base import Build, Languages, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd, get_files_from_dir_with_patterns


def iterate_over_all_files(frama_c: str, build: str, source_dir: str, result_dir: str):
    for src in os.listdir(source_dir):
        full_path = os.path.join(source_dir, src)
        if os.path.isdir(full_path):
            iterate_over_all_files(frama_c, build, full_path, result_dir)
        elif src.endswith(".c"):
            name_without_extension = os.path.splitext(src)[0]

            if name_without_extension[-1].isalpha():
                name_without_extension = name_without_extension[:-1]
            full_path_src = os.path.join(source_dir, name_without_extension)
            print("iterating over", source_dir)
            testcase_support_dir = os.path.join(source_dir, os.pardir, os.pardir, os.pardir, "testcasesupport/")
            cmd = ("/opt/opam/default/bin/frama-c -cpp-command=\"gcc -C -E -DOMITGOOD -DINCLUDEMAIN=ON "
                   "-I" + testcase_support_dir +
                   "\" -no-autoload-plugins -load-plugin=eva,from,scope,inout,markdown-report -eva -eva-no-results"
                   " -mdr-gen sarif -mdr-sarif-deterministic " + testcase_support_dir +"*.c " + full_path_src +
                   "*.c -mdr-no-print-libc -eva-slevel 10 -mdr-out " + os.path.join(result_dir,
                                                                     name_without_extension) + "_bad_report.sarif")
            run_cmd(cmd)
            cmd = ("/opt/opam/default/bin/frama-c -cpp-command=\"gcc -C -E -DOMITBAD -DINCLUDEMAIN=ON "
                   "-I" + testcase_support_dir +
                   "\" -no-autoload-plugins -load-plugin=eva,from,scope,inout,markdown-report -eva -eva-no-results"
                   " -mdr-gen sarif -mdr-sarif-deterministic " + testcase_support_dir + "*.c " + full_path_src +
                   "*.c -mdr-no-print-libc -eva-slevel 10 -mdr-out " + os.path.join(result_dir,
                                                                     name_without_extension) + "_good_report.sarif")
            run_cmd(cmd)


def run(frama_c: str, build: str, source_dir: str, result_dir: str, language: str):
    iterate_over_all_files(frama_c, build, source_dir, result_dir)


class FramaCRunner(ToolRunner):
    DEFAULT_PATH = "/opt/opam/default/bin/frama-c"
    SUPPORTED_CWE_TYPES = ["double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        run(self.tool_path, build, src_dir, res_dir, language)
