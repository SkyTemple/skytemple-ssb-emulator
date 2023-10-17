from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="skytemple-ssb-emulator",
    rust_extensions=[RustExtension(f"skytemple_ssb_emulator", binding=Binding.PyO3)], # set debug=True for unoptimized build.
    packages=["skytemple_ssb_emulator"],
    zip_safe=False,
)
