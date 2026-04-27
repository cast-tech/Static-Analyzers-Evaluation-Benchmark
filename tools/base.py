from enum import Enum
import json
import os


def discover_tools() -> list:
    tools_dir = os.path.dirname(__file__)
    tool_names = []
    for entry in os.scandir(tools_dir):
        if entry.is_dir():
            tool_name = entry.name
            runner_file = os.path.join(entry.path, f"run_{tool_name}.py")
            extractor_file = os.path.join(entry.path, f"extract_{tool_name}.py")
            if os.path.isfile(runner_file) and os.path.isfile(extractor_file):
                tool_names.append(tool_name)
    return sorted(tool_names)


class CweTypes(Enum):
    MEMORY_LEAK = "memory_leak"
    DOUBLE_FREE = "double_free"
    USE_AFTER_FREE = "use_after_free"


class Build(Enum):
    CMAKE = "CMake"
    FILES = "files"
    CONF = "configure"


class Languages(Enum):
    C = "C"
    CPP = "CPP"


CMAKE_ARG_FOR_LANGUAGE = {
    Languages.C.value: "-DENABLE_C=ON ",
    Languages.CPP.value: "-DENABLE_CPP=ON ",
}


class Source:
    def __init__(self, name: str, cwe_type: str, languages: list,
                 reg_path: str, path_to_src: str, verbose: bool = False,
                 build_type: str = Build.FILES.value):

        self.name = name
        self.cwe_type = cwe_type
        self.languages = languages
        self.reg_path = reg_path
        self.path = os.path.join(path_to_src, self.reg_path)
        self.verbose = verbose
        self.build = build_type

    def __repr__(self) -> str:
        return (f"Source(name={self.name}, cwe_type={self.cwe_type}, languages={self.languages}"
                f"reg_path={self.reg_path}, path={self.path}, verbose={self.verbose}, "
                f"build={self.build})")

    def serialize(self) -> dict:
        return {
            "name": self.name,
            "cwe_type": self.cwe_type,
            "languages": self.languages,
            "reg_path": self.reg_path,
            "verbose": self.verbose,
            "build": self.build
        }

    @staticmethod
    def deserialize(source_data: dict, path_to_src: str) -> 'Source':
        return Source(
            name=source_data["name"],
            cwe_type=source_data["cwe_type"],
            languages=source_data["languages"],
            reg_path=source_data["reg_path"],
            path_to_src=path_to_src,
            verbose=source_data["verbose"],
            build_type=source_data["build"]
        )


class Test:
    def __init__(self, sources: list):
        self.sources = sources

    def __repr__(self) -> str:
        return f"Test(sources={self.sources})"

    def serialize(self) -> dict:
        return {
            "sources": [source.serialize() for source in self.sources]
        }

    @staticmethod
    def deserialize(test_data: dict, path_to_src: str) -> 'Test':
        sources = [Source.deserialize(source_data, path_to_src) for source_data in test_data["sources"]]
        return Test(sources=sources)

    def save_to_json(self, file_path: str):
        with open(file_path, 'w') as json_file:
            json.dump(self.serialize(), json_file, indent=4)

    @classmethod
    def load_from_json(cls, file_path: str, path_to_src: str):
        with open(file_path, 'r', encoding='utf-8') as json_file:
            data = json.load(json_file)
            return cls.deserialize(data, path_to_src)
