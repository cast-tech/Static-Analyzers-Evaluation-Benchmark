# Memory Tracer Tests


## Supports

### Tools:
* infer (v1.2.0)
* scan-build (in llvm-21.1.8) (scan-build wrapper is used instead of CSA directly)
* KLEE (v3.1)
* ikos (v3.5)
* smatch (v0.5.0-8814-g34981e51)
* frama-c (v32.0)
* CPAchecker (4.0-603-g9c8152baa7 (OpenJDK 64-Bit Server VM 17.0.14))
* symbiotic (v10)
* CBMC (v6.5.0)
* CodeChecker (in llvm-21.1.8)
* Cppcheck (v2.19.0)
* SVF (v3.2)

### Languages:
* C
* C++

### CWE Types:
* CWE 401: Memory Leak
* CWE 415: Double Free
* CWE 416: Use After Free


## External Packages
* python3
* pip3
* Docker (tools run inside containers)
* Python packages listed in `requirements.txt` (`docker`, `libclang`, `chardet`, `cxxfilt`)
* A `libclang.so` on the host for the evaluation step (pass its path with `--lib-clang`)


## Run
Note: All paths of files shown in this `README.md` are relative to the project root.

Set up a virtual environment and install the Python dependencies:
```shell
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`run_tools.py` is the main entry point: it builds the per-tool Docker image,
runs the selected analyzer on the configured test suites inside a container,
then evaluates the results on the host. Usage:
```shell
PATH_TO/python3 run_tools.py (--infer | --scan-build | --ikos | --klee | --smatch |
                              --frama-c | --cpachecker | --symbiotic | --cbmc |
                              --codechecker | --cppchecker | --svf)
                             [--lib-clang <path>] [--config <path>]
                             [--result <path>] [--image-build-disable]
```
* For more information run with --help.
* Tool flags are auto-discovered from `tools/<name>/` directories that contain both `run_<name>.py` and `extract_<name>.py`.
* Each tool will run only if it's set from argument list. At least one of the tools must be selected.
* If result path is not set, it will be generated automatically (Format: %d_%m_%Y_%H_%M_%S_%f_static_analysis_result).
* If there is an image of a given tool already, and you want to skip process of building a new one, set 
`--image-build-disable`.
* `--lib-clang` optionally points to a host `libclang.so` used during the evaluation step; if omitted, the Python `libclang` package is used instead.
* Select test suite configuration by using `--config`. Default value is `test_suite_config.json`.

### Usage examples:
This example will run infer on test suites specified in `test_suite_config.json` on docker container after building an 
image for infer. Result and lib-clang paths will be set with their default values:
```shell
PATH_TO/python3 run_tools.py --infer
```

If there is an already built image, and you want to skip the process of building it again you can use:
```shell
PATH_TO/python3 run_tools.py --infer --image-build-disable
```

### Result:
* The final rates will be in JSON format file - `RESULT_PATH/TOOL_NAME_rates.json`
* Each tool will have its own output directory - `RESULT_PATH/TOOL_NAME_output`
* Tool's classified results for each source file -`RESULT_PATH/TOOL_NAME_output/.../TOOL_NAME_classified_results.json`

## Integrating new tools
This project supports the integration of additional tools. Tool flags, runners, and
extractors are all auto-discovered from the `tools/` directory layout — no changes to
`run_tools.py` or `tools/base.py` are required. Follow the steps below to add a new tool:

1. Create the tool's directory:

   The tool should have its own directory under `tools/`, named after the tool (snake_case).
For example: `tools/tool_name`. The directory should contain:

   * Dockerfile — sets up the project and the tool ready for execution in the Docker environment
   * Runner (`run_tool_name.py`) — implements the `ToolNameRunner` class with:
   ```
   def execute(self, src_dir, res_dir, build, language):
   ```
   * Output extractor (`extract_tool_name.py`) — implements the `ToolNameExtractor` class with:
   ```
   def extract(self, result_file_path, cwe_type):
   def collect_result_files(self, result_dir):  # Optional. Set a custom way to collect output files from the
                                                # result directory. By default, it collects all *.sarif files recursively
   ```
   * Additional dependencies — any necessary installer scripts, archives, or other setup files

   Both `run_tool_name.py` and `extract_tool_name.py` must be present; `discover_tools()`
   in `tools/base.py` skips directories missing either.

2. Document the changes:

   Once the tool is integrated, update the README to document its name, version with any
   additional information (if any).
