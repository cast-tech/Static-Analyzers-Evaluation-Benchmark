import os.path

from tools.run_tool import ToolRunner
from tools.base import Build, CMAKE_ARG_FOR_LANGUAGE
from tools.support import run_cmd
from tools.build import MAKE_CMD, get_compiler, get_source_files


all_default_checkers = [
    "core.CallAndMessage",
    "core.DivideZero",
    "core.NonNullParamChecker",
    "core.NullDereference",
    "core.StackAddressEscape",
    "core.UndefinedBinaryOperatorResult",
    "core.VLASize",
    "core.uninitialized.ArraySubscript",
    "core.uninitialized.Assign",
    "core.uninitialized.Branch",
    "core.uninitialized.CapturedBlockVariable",
    "core.uninitialized.NewArraySize",
    "core.uninitialized.UndefReturn",
    "cplusplus.InnerPointer",
    "cplusplus.Move",
    "cplusplus.NewDelete",
    "cplusplus.NewDeleteLeaks",
    "cplusplus.PlacementNew",
    "cplusplus.PureVirtualCall",
    "cplusplus.StringChecker",
    "deadcode.DeadStores",
    "nullability.NullPassedToNonnull",
    "nullability.NullReturnedFromNonnull",
    "security.insecureAPI.UncheckedReturn",
    "security.insecureAPI.getpw",
    "security.insecureAPI.gets",
    "security.insecureAPI.mkstemp",
    "security.insecureAPI.mktemp",
    "security.insecureAPI.vfork",
    "unix.API",
    "unix.Malloc",
    "unix.MallocSizeof",
    "unix.MismatchedDeallocator",
    "unix.Vfork",
    "unix.cstring.BadSizeArg",
    "unix.cstring.NullArg"
]

checkers_to_enable = [
    "unix.Malloc",
    "cplusplus.NewDelete",
    "cplusplus.NewDeleteLeaks",
    "cplusplus.InnerPointer",
    "cplusplus.Move"
]


def checkers_diff(checkers_use: list) -> list:
    return [i for i in all_default_checkers + checkers_use
            if i not in all_default_checkers or i not in checkers_use]


def construct_arguments(max_loop: int = 4, stats: bool = False, headers: bool = False):
    arguments = list()

    arguments.extend(["-sarif", "-o", "result"])
    arguments.extend(["-maxloop", str(max_loop)])

    if stats:
        arguments.extend(["-stats", "-internal-stats"])
    if headers:
        arguments.extend(["-analyze-headers"])

    for disable_checker in checkers_diff(checkers_to_enable):
        arguments.extend(["-disable-checker", disable_checker])
    for enable_checker in checkers_to_enable:
        arguments.extend(["-enable-checker", enable_checker])

    return " ".join(arguments) + " "


class ScanBuildRunner(ToolRunner):
    DEFAULT_PATH = "/opt/LLVM-21.1.8-Linux-X64/bin/scan-build"
    SUPPORTED_CWE_TYPES = ["memory_leak", "double_free", "use_after_free"]
    SUPPORTED_LANGUAGES = ["C", "CPP"]

    def execute(self, src_dir: str, res_dir: str, build: str, language: str):
        command_prefix = self.tool_path + " " + construct_arguments()

        if build == Build.CONF.value:
            run_cmd(command_prefix + os.path.join(src_dir, "configure"), res_dir)
        if build == Build.CMAKE.value:
            run_cmd(command_prefix + "cmake " + CMAKE_ARG_FOR_LANGUAGE[language] + " -DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF " + src_dir, res_dir)

        postfix = MAKE_CMD
        if build == Build.FILES.value:
            c_files = get_source_files(src_dir, language)
            if not c_files:
                return
            postfix = get_compiler(language) + " " + c_files

        run_cmd(command_prefix + postfix, res_dir)
