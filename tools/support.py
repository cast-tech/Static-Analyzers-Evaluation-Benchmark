from pathlib import Path
import subprocess
import datetime
import shutil
import sys
import os

from .base import Build

LIB_CLANG_IS_SET = False


def set_clang_lib(path_to: str):
    global LIB_CLANG_IS_SET
    if not LIB_CLANG_IS_SET:
        import clang.cindex as cl
        if path_to:
            cl.Config.set_library_file(os.path.realpath(path_to))
        LIB_CLANG_IS_SET = True


def get_files_from_dir_with_patterns(directory: str, patterns: list) -> list:
    return [str(f) for pattern in patterns for f in Path(directory).glob(pattern)]


def create_dir(path: str) -> str:
    if os.path.exists(path):
        path = os.path.join(os.path.dirname(path),
                            datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S_%f_")[:-3] + "result")

    os.makedirs(path)
    return path


def ensure_directory_exists(directory_path: str, reserve_path = None) -> str:
    try:
        if not os.path.exists(directory_path):
            os.makedirs(directory_path)
            print(f"Created directory: {directory_path}")
        else:
            print(f"Directory already exists: {directory_path}")
    except PermissionError:
        print(f"Permission denied: Unable to create directory at {directory_path}")
        if reserve_path:
            directory_path = reserve_path
            print(f"Attempting to create reserve path: {directory_path}")
            try:
                os.makedirs(directory_path, exist_ok=True)
            except (PermissionError, OSError) as e:
                print(f"Failed to create reserve path: {directory_path}. Error: {e}")
                sys.exit("Critical Error: Unable to create necessary directories.")
        else:
            print(f"No reserve path is set. Exiting.")
            sys.exit("Critical Error: Unable to create necessary directories.")
    except OSError as e:
        print(f"Failed to create directory {directory_path}: {e}")
        sys.exit("Critical Error: Unable to create necessary directories.")

    return directory_path


def run_cmd(command, dir_to_run=None):
    """Run a shell command. Pass a list for safe shell=False execution,
    or a str for commands that require shell features (redirections, pipes, etc.)."""
    use_shell = isinstance(command, str)
    display = command if use_shell else " ".join(command)
    exit_code = subprocess.call(command, shell=use_shell, cwd=dir_to_run)
    if exit_code != 0:
        raise RuntimeError(display + "\nFailure with exit code: " + str(exit_code))


def run_cmd_cbmc(name_without_extension: str, failed_files: list, command, dir_to_run=None):
    """Run a CBMC command; silently records files that crash with SIGABRT (exit 134)."""
    use_shell = isinstance(command, str)
    exit_code = subprocess.call(command, shell=use_shell, cwd=dir_to_run)
    if exit_code == 134:
        failed_files.append(name_without_extension)

def copy_file(source_path: str, destination_path: str):
    try:
        shutil.copy(source_path, destination_path)
        print(f"File copied from {source_path} to {destination_path}")
    except FileNotFoundError:
        print(f"Copy failed. File not found: {source_path}")
        sys.exit("Critical Error: Unable to copy necessary files.")
    except PermissionError:
        print(f"Copy failed. Permission denied while copying to: {destination_path}")
        sys.exit("Critical Error: Unable to copy necessary files.")
    except Exception as e:
        print(f"Copy failed. An error occurred: {e}")
        sys.exit("Critical Error: Unable to copy necessary files.")



def get_main_result_path(source_path: str, fixed_timestamp: str) -> str:
    result_dir_name = fixed_timestamp + "_static_analysis_result"
    result = os.path.join(source_path, result_dir_name)

    return str(result)


def get_tool_result_path(result_path: str , tool_name: str, out_suffix: str) -> str:
    return str(os.path.join(result_path, tool_name + out_suffix))


def change_paths_base(source_base_path: str, target_base_path: str, source_path: str) -> str:
    rel_path = os.path.relpath(source_path, source_base_path)
    return os.path.join(target_base_path, rel_path)


def get_result_path(main_result_path: str, src_path: str, path_to_src: str, language: str) -> str:
    reg_suffix = os.path.relpath(src_path, path_to_src)
    return os.path.join(main_result_path, reg_suffix, language)


def get_tool_default_path(path_to_src, tool_name):
    import importlib
    module = importlib.import_module(f"tools.{tool_name}.run_{tool_name}")
    class_name = tool_name.replace("_", " ").title().replace(" ", "") + "Runner"
    runner_class = getattr(module, class_name)
    return os.path.join(path_to_src, runner_class.DEFAULT_PATH)


def collect_sources(test_source):
    from_files = test_source.build == Build.FILES.value
    sub_dirs = os.listdir(test_source.path)

    for sub_dir in sub_dirs:
        source_dir = os.path.join(test_source.path, sub_dir)
        sources = [source_dir] if not from_files else os.listdir(source_dir)

        for source in sources:
            if from_files:
                source = os.path.join(source_dir, source)

            yield source
