import os
import subprocess

from tools.base import Languages, CMAKE_ARG_FOR_LANGUAGE
from tools.support import get_files_from_dir_with_patterns, run_cmd

MAKE_CMD = "make -j $(($(nproc --all) - $(nproc --all)/4))"


def get_compiler(language: str) -> str:
    return "clang" if language == Languages.C.value else "clang++"


def get_source_files(src_dir: str, language: str) -> str:
    """Returns space-joined source files string, or '' if none found."""
    pattern = ["*.c"] if language == Languages.C.value else ["*.cpp"]
    return " ".join(get_files_from_dir_with_patterns(src_dir, pattern))


def find_executables(
    result_dir: str,
    skip_dirs: list[str] = None,
    excluded_extensions: tuple[str, ...] = None,
) -> list[str]:
    """Walk result_dir and return paths of executable files.

    Args:
        skip_dirs:            Directory name fragments to skip (e.g. ["CMakeFiles"]).
        excluded_extensions:  File extensions to exclude (e.g. (".c", ".o", ".so")).
    """
    executables = []
    for root, _, files in os.walk(result_dir):
        if skip_dirs and any(skip in root for skip in skip_dirs):
            continue
        for f in files:
            if excluded_extensions and f.endswith(excluded_extensions):
                continue
            path = os.path.join(root, f)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                executables.append(path)
    return executables


def generate_bitcode(result_dir: str):
    """Run extract-bc on every executable in result_dir, skipping CMakeFiles."""
    for exe_path in find_executables(result_dir, skip_dirs=["CMakeFiles"]):
        print(f"Generating bitcode for {exe_path}")
        run_cmd(f"extract-bc {exe_path}", os.path.dirname(exe_path))


def cmake_build_stage(
    c_compiler: str,
    cxx_compiler: str,
    src_dir: str,
    res_dir: str,
    language: str,
    extra_cmake_args: list[str] = None,
    extra_make_args: list[str] = None,
    job_count: int = None,
    env: dict = None,
    skip_install: bool = False,
):
    """CMake build stage with configurable compilers. Runs cmake, make, and optionally make install.

    Args:
        extra_cmake_args: Additional -D or other flags passed to cmake.
        extra_make_args:  Additional flags passed to both make invocations.
        job_count:        Number of parallel jobs for make (-j). Defaults to all available cores.
        env:              Extra environment variables merged into the subprocess environment.
        skip_install:     Skip the make install step. Use when partial builds are expected
                          (e.g. -k) and installed files are not needed — built artifacts are
                          already in res_dir via -B.
    """
    import multiprocessing
    import os

    merged_env = {**os.environ, **(env or {})}
    job_count = job_count if job_count is not None else multiprocessing.cpu_count()

    cmake_cmd = [
        "cmake", "-B", res_dir,
        f"-DCMAKE_C_COMPILER={c_compiler}",
        f"-DCMAKE_CXX_COMPILER={cxx_compiler}",
        "-DCMAKE_C_FLAGS=-g",
        "-DCMAKE_CXX_FLAGS=-g",
        f"-DCMAKE_INSTALL_PREFIX={res_dir}",
        CMAKE_ARG_FOR_LANGUAGE[language].strip(),
        "-DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF",
        *(extra_cmake_args or []),
        src_dir,
    ]
    make_cmd = ["make", "-k", f"-j{job_count}", *(extra_make_args or [])]

    subprocess.run(cmake_cmd, check=True, env=merged_env)
    subprocess.run(make_cmd, cwd=res_dir, check=False, env=merged_env)

    if not skip_install:
        make_install_cmd = ["make", "install", "-k", f"-j{job_count}", *(extra_make_args or [])]
        subprocess.run(make_install_cmd, cwd=res_dir, check=False, env=merged_env)


def cmake_compile_commands(
    src_dir: str,
    res_dir: str,
    language: str,
    extra_cmake_args: list[str] = None,
    env: dict = None,
):
    """Run cmake to generate compile_commands.json (no custom compiler, no make).

    Suitable for tools that consume a compilation database directly (e.g. CPAChecker).
    """
    merged_env = {**os.environ, **(env or {})}
    cmake_cmd = [
        "cmake", "-B", res_dir,
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        CMAKE_ARG_FOR_LANGUAGE[language].strip(),
        "-DPLACE_OUTPUT_IN_TOPLEVEL_DIR=OFF",
        *(extra_cmake_args or []),
        src_dir,
    ]
    subprocess.run(cmake_cmd, check=True, env=merged_env)


def configure_compile_commands(
    src_dir: str,
    res_dir: str,
    extra_configure_args: list[str] = None,
    extra_make_args: list[str] = None,
    job_count: int = None,
    env: dict = None,
):
    """Run ./configure then bear -- make to capture compile_commands.json.

    Suitable for tools that consume a compilation database directly (e.g. CPAChecker).
    """
    import multiprocessing

    merged_env = {**os.environ, **(env or {})}
    job_count = job_count if job_count is not None else multiprocessing.cpu_count()

    configure_cmd = [os.path.join(src_dir, "configure"), *(extra_configure_args or [])]
    make_cmd = ["bear", "--", "make", "-k", f"-j{job_count}", *(extra_make_args or [])]

    subprocess.run(configure_cmd, cwd=res_dir, check=False, env=merged_env)
    subprocess.run(make_cmd, cwd=res_dir, check=False, env=merged_env)


def configure_build_stage(
    c_compiler: str,
    cxx_compiler: str,
    src_dir: str,
    res_dir: str,
    extra_configure_args: list[str] = None,
    extra_make_args: list[str] = None,
    job_count: int = None,
    env: dict = None,
):
    """Configure build stage. Runs ./configure then make and make install.

    Args:
        extra_configure_args: Additional arguments passed to the configure script.
        extra_make_args:      Additional flags passed to both make invocations.
        job_count:            Number of parallel jobs for make (-j). Defaults to all available cores.
        env:                  Extra environment variables merged into the subprocess environment.
    """
    import multiprocessing

    merged_env = {**os.environ, **(env or {})}
    job_count = job_count if job_count is not None else multiprocessing.cpu_count()

    configure_cmd = [
        os.path.join(src_dir, "configure"),
        f"CC={c_compiler}",
        f"CXX={cxx_compiler}",
        *(extra_configure_args or []),
    ]
    make_cmd = ["make", "-k", f"-j{job_count}", *(extra_make_args or [])]
    make_install_cmd = ["make", "install", "-k", f"-j{job_count}", *(extra_make_args or [])]

    subprocess.run(configure_cmd, cwd=res_dir, check=False, env=merged_env)
    subprocess.run(make_cmd, cwd=res_dir, check=False, env=merged_env)
    subprocess.run(make_install_cmd, cwd=res_dir, check=False, env=merged_env)
