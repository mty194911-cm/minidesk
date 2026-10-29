# Build: python setup.py build_ext --inplace   (MinGW, see setup.cfg)
from setuptools import Extension, setup
from Cython.Build import cythonize

common = dict(
    include_dirs=["native"],
    define_macros=[("MS_WIN64", None)],  # required for 64-bit Python + MinGW
    extra_compile_args=["-O3"],
    extra_link_args=["-static"],  # no MinGW runtime DLLs at import time,
)

setup(
    ext_modules=cythonize(
        [
            Extension("capture", ["native/capture.pyx", "native/dxcap.cpp"], language="c++",
                      libraries=["d3d11", "dxgi", "user32"], **common),
            Extension("winput", ["native/winput.pyx"], libraries=["user32", "winmm"], **common),
        ],
        language_level=3,
    )
)
