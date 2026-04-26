from os.path import dirname
import argparse
import datetime
import fcntl
import tarfile
import chardet
import sys
import os
import docker

from tools.base import discover_tools, Test
from tools.host_evaluator import evaluate_tool
from tools.support import (
    copy_file,
    get_main_result_path,
    get_tool_result_path,
    get_tool_default_path,
    ensure_directory_exists,
)

PATH_TO_SRC = dirname(os.path.realpath(os.path.abspath(__file__)))
DOCKER_PATH_TO_SRC = "/memory-tracer-tests"
OUT_SUFFIX = "_output"
FIXED_TIMESTAMP = datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S_%f")

BASE_IMAGE_DOCKERFILE = os.path.join("tools", "base", "Dockerfile")
# Ubuntu version required per tool. All unlisted tools default to 22.04.
TOOL_UBUNTU_VERSION = {
    "klee": "20.04",
    "svf":  "24.04",
}
DEFAULT_UBUNTU_VERSION = "22.04"


def get_ubuntu_version(tool_name: str) -> str:
    return TOOL_UBUNTU_VERSION.get(tool_name, DEFAULT_UBUNTU_VERSION)


def base_image_tag(ubuntu_version: str) -> str:
    return f"static-analyzers-eval-base:{ubuntu_version}"


def parse_args(arg_list: list) -> argparse.Namespace:
    lib_clang_default = os.path.join(PATH_TO_SRC, "third-party", "llvm", "lib", "libclang.so.16")
    config_default = os.path.join(PATH_TO_SRC, "test_suite_config.json")
    result_default = get_main_result_path(PATH_TO_SRC, FIXED_TIMESTAMP)

    tool_names = discover_tools()
    tool_flags = " | ".join(f"--{t.replace('_', '-')}" for t in tool_names)

    arg_parser = argparse.ArgumentParser(
        description=(
            "This script is for running and calculating "
            "results of the given memory related error analysers."
        ),
        usage=(
            f"PATH_TO_PYTHON_BIN PATH_TO_SCRIPT ({tool_flags}) "
            "[--lib-clang <path>] "
            "[--config <path>] [--result <path>] "
            "[--image-build-disable]"
        )
    )

    for tool_name in tool_names:
        flag = f"--{tool_name.replace('_', '-')}"
        arg_parser.add_argument(flag, dest=tool_name,
                                help=f"Enable {tool_name}", action="store_true", default=False)

    arg_parser.add_argument("--lib-clang", dest="lib_clang",
                            help="Path to clang library", default="", required=False)
    arg_parser.add_argument("--config", dest="config_path",
                            help="JSON file path where test suite configuration is stored.")
    arg_parser.add_argument("--result", dest="result_dir",
                            help="The directory path to store the results.", default=result_default)
    arg_parser.add_argument("--image-build-disable", dest="image_build_disable",
                            help="Disable image building processes, if the images already exist",
                            action="store_true", default=False)

    args = arg_parser.parse_args(arg_list)
    args._tool_names = tool_names
    check_args(arg_parser, args, tool_names)

    for tool_name in tool_names:
        path_attr = f"{tool_name}_path"
        if not getattr(args, path_attr, None):
            setattr(args, path_attr, get_tool_default_path(PATH_TO_SRC, tool_name))

    if args.config_path:
        copy_file(args.config_path, config_default)
    args.config_path = config_default

    return args


def check_args(arg_parser: argparse.ArgumentParser, args: argparse.Namespace, tool_names: list):
    if not any(getattr(args, tool_name, False) for tool_name in tool_names):
        arg_parser.error("You have to set at least one tool to run this script!")
    if args.lib_clang and not os.path.exists(args.lib_clang):
        arg_parser.error(f"Given library file doesn't exist: {args.lib_clang}")
    if args.config_path and not os.path.exists(args.config_path):
        arg_parser.error(f"Given test suite configuration file doesn't exist: {args.config_path}")

    reserve_result_path = get_main_result_path(PATH_TO_SRC, FIXED_TIMESTAMP)
    args.result_dir = ensure_directory_exists(args.result_dir, reserve_result_path)
    if not os.access(args.result_dir, os.W_OK):
        arg_parser.error(
            f"Result directory is not writable by current user (uid={os.getuid()}): {args.result_dir}. "
            f"If it was created by a previous Docker run as root, remove it or chown it."
        )


def _write_dockerignore(tool_name: str, all_tool_names: list):
    """Write a .dockerignore that excludes other tools' directories (large binaries)."""
    dockerignore_path = os.path.join(PATH_TO_SRC, ".dockerignore")
    lines = []
    for other_tool in all_tool_names:
        if other_tool != tool_name:
            lines.append(f"tools/{other_tool}/")
    with open(dockerignore_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return dockerignore_path


def build_base_image(ubuntu_version: str, disable_build: bool,
                     all_tool_names: list) -> None:
    """Build the shared base image for the given Ubuntu version."""
    tag = base_image_tag(ubuntu_version)
    if disable_build:
        print(f"Skipping base image build for {tag} (--image-build-disable)")
        return

    docker_client = docker.from_env()
    lock_path = os.path.join(PATH_TO_SRC, ".dockerignore.lock")
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        # Exclude all tool dirs — the base image needs none of their binaries.
        dockerignore_path = _write_dockerignore("base", all_tool_names)
        print(f"Building base image {tag}. This may take a while...")
        try:
            for log in docker_client.api.build(
                    path=PATH_TO_SRC,
                    tag=tag,
                    dockerfile=BASE_IMAGE_DOCKERFILE,
                    buildargs={"UBUNTU_VERSION": ubuntu_version},
                    decode=True
            ):
                if "stream" in log:
                    print(log["stream"], end="", flush=True)
                if "status" in log:
                    progress = log.get("progress", "")
                    print(f"{log['status']} {progress}".strip(), flush=True)
                if "error" in log:
                    print(f"ERROR: {log['error']}", flush=True)
        finally:
            if os.path.exists(dockerignore_path):
                os.remove(dockerignore_path)


def build_tool_image(tool_name: str, disable_build: bool,
                     all_tool_names: list) -> "docker.client.DockerClient":
    docker_client = docker.from_env()
    dockerfile_path = os.path.join("tools", tool_name, "Dockerfile")

    if disable_build:
        print("Skipping the process of building the tool image")
        return docker_client

    # Serialize builds so concurrent run_tools.py invocations don't clobber each other's .dockerignore.
    lock_path = os.path.join(PATH_TO_SRC, ".dockerignore.lock")
    with open(lock_path, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        dockerignore_path = _write_dockerignore(tool_name, all_tool_names)
        print(f"Building docker image for the tool: {tool_name}. This may take a while...")
        try:
            for log in docker_client.api.build(
                    path=PATH_TO_SRC,
                    tag=f"{tool_name}_image:latest",
                    dockerfile=dockerfile_path,
                    decode=True
            ):
                if "stream" in log:
                    print(log["stream"], end="", flush=True)
                if "status" in log:
                    progress = log.get("progress", "")
                    print(f"{log['status']} {progress}".strip(), flush=True)
                if "error" in log:
                    print(f"ERROR: {log['error']}", flush=True)
        finally:
            if os.path.exists(dockerignore_path):
                os.remove(dockerignore_path)

    return docker_client


def run_tool_inside_container(tool_name: str, docker_client: "docker.client.DockerClient", tool_cmd: str,
                              config_path: str, host_result_dir: str, container_result_dir: str):
    container_name = f"{tool_name}_container_" + FIXED_TIMESTAMP
    image_name = tool_name + "_image:latest"
    print(f"Running the container for image {image_name} with name {container_name}")

    container = docker_client.containers.run(
        image_name,
        detach=True,
        name=container_name,
        command=f"python3 tools/tool_runner_docker.py {tool_cmd}",
        user=f"{os.getuid()}:{os.getgid()}",
        volumes={
            config_path: {"bind": f"{DOCKER_PATH_TO_SRC}/test_suite_config.json", "mode": "ro"},
            host_result_dir: {"bind": container_result_dir, "mode": "rw"},
        },
    )

    print(f"Container is up. Streaming {tool_name} runner output...")
    for line in container.logs(stream=True):
        encoding = chardet.detect(line)['encoding'] or 'utf-8'
        print(line.decode(encoding), end='')

    exit_code = container.wait()["StatusCode"]
    if exit_code != 0:
        print(f"{tool_name} runner failed with exit code {exit_code}")
    else:
        print(f"{tool_name} runner executed successfully")

    return container, exit_code == 0


def run_tool_on_docker(tool_name: str, args: argparse.Namespace):
    container = None
    container_result_dir = get_main_result_path(DOCKER_PATH_TO_SRC, FIXED_TIMESTAMP)
    container_tool_result = get_tool_result_path(container_result_dir, tool_name, OUT_SUFFIX)
    tool_cmd = " ".join(["--result", container_tool_result,
                         "--tool-name", tool_name])
    tool_ran_successfully = False
    try:
        docker_client = build_tool_image(tool_name, args.image_build_disable, args._tool_names)
        container, tool_ran_successfully = run_tool_inside_container(
            tool_name, docker_client, tool_cmd, args.config_path,
            args.result_dir, container_result_dir)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"An error occurred when running {tool_name}: {e}\n"
              f"Cleaning up the container...")
    finally:
        if container:
            container.stop()
            container.remove()

    if tool_ran_successfully:
        print(f"Running evaluation for {tool_name} on host...")
        host_tool_result = get_tool_result_path(args.result_dir, tool_name, OUT_SUFFIX)
        test = Test.load_from_json(args.config_path, PATH_TO_SRC)
        evaluate_tool(tool_name, host_tool_result, test, args.lib_clang)


def ensure_test_suites_extracted():
    test_suites_dir = os.path.join(PATH_TO_SRC, "test_suites")
    archive_path = os.path.join(test_suites_dir, "archived_test_suites.tar.gz")
    marker = os.path.join(test_suites_dir, ".extracted")

    if os.path.exists(marker):
        return
    if not os.path.exists(archive_path):
        print(f"Warning: test suites archive not found at {archive_path}")
        return

    print("Extracting test suites for host evaluation...")
    with tarfile.open(archive_path, "r:gz") as tar:
        tar.extractall(path=test_suites_dir)

    # Atomic marker publish: write to a temp file, then rename. If extraction
    # above raises, no marker is created and the next run will re-extract.
    tmp_marker = marker + ".tmp"
    with open(tmp_marker, "w"):
        pass
    os.replace(tmp_marker, marker)
    print("Test suites extracted.")


def run_tools(args: argparse.Namespace):
    ensure_test_suites_extracted()
    enabled_tools = [tool for tool in args._tool_names if getattr(args, tool, False)]

    # Build one base image per Ubuntu version needed by the enabled tools.
    needed_versions = {get_ubuntu_version(t) for t in enabled_tools}
    for version in sorted(needed_versions):
        build_base_image(version, args.image_build_disable, args._tool_names)

    for tool_name in enabled_tools:
        run_tool_on_docker(tool_name, args)


def main(arg_list: list):
    args = parse_args(arg_list)
    run_tools(args)

    print("\nYou can check results in", args.result_dir)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception as err:
        print(str(err))
        exit(1)
