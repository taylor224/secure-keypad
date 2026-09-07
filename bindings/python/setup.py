"""Build glue: compiles the C core (../../core) with CMake into a static library, then lets cffi build the
API-mode extension `secure_keypad_server._skp` that links it statically. See build_skp.py for the FFI."""
import os
import shutil
import subprocess
import sys

from setuptools import setup
from setuptools.command.build_ext import build_ext

HERE = os.path.abspath(os.path.dirname(__file__))
CORE_DIR = os.environ.get("SKP_CORE_DIR", os.path.normpath(os.path.join(HERE, "..", "..", "core")))
CORE_BUILD = os.path.join(HERE, "build", "core")


def find_cmake():
    candidates = [
        os.environ.get("CMAKE"),
        shutil.which("cmake"),
        os.path.expanduser("~/Library/Android/sdk/cmake/3.22.1/bin/cmake"),
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    raise RuntimeError("cmake >= 3.20 is required to build secure-keypad-server (set CMAKE=/path/to/cmake)")


def build_core():
    if not os.path.exists(os.path.join(CORE_DIR, "CMakeLists.txt")):
        raise RuntimeError(f"C core not found at {CORE_DIR} (set SKP_CORE_DIR)")
    cmake = find_cmake()
    os.makedirs(CORE_BUILD, exist_ok=True)
    configure = [
        cmake, "-S", CORE_DIR, "-B", CORE_BUILD,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DSKP_BUILD_TESTS=OFF",
        "-DSKP_TESTING=OFF",
        "-DSKP_BUILD_SHARED=OFF",
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
    ]
    if shutil.which("ninja") and not os.path.exists(os.path.join(CORE_BUILD, "Makefile")):
        configure += ["-G", "Ninja"]
    subprocess.check_call(configure)
    subprocess.check_call([cmake, "--build", CORE_BUILD, "--target", "skp_static", "--config", "Release"])
    lib = os.path.join(CORE_BUILD, "libskp.a")
    if not os.path.exists(lib):
        raise RuntimeError("libskp.a was not produced by the core build")
    return lib


class BuildExt(build_ext):
    def run(self):
        build_core()
        super().run()


setup(
    cffi_modules=["build_skp.py:ffibuilder"],
    cmdclass={"build_ext": BuildExt},
)
