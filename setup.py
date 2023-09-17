__version__ = '1.6.0b1'

from setuptools import setup
from setuptools_rust import Binding, RustExtension

# README read-in
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()
# END README read-in

setup(
    name="skytemple-ssb-emulator",
    version=__version__,
    rust_extensions=[RustExtension(f"skytemple_ssb_emulator", binding=Binding.PyO3)], # set debug=True for unoptimized build.
    packages=["skytemple_ssb_emulator"],
    package_data={"skytemple_ssb_emulator": ["py.typed", "*.pyi"]},
    install_requires=[
        'range-typed-integers >= 1.0.0'
    ],
    description='Emulator runtime and bindings for skytemple-ssb-debugger.',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    url='https://github.com/SkyTemple/skytemple-ssb-emulator/',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python',
        'Programming Language :: Rust',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    include_package_data=True,
)
