import unittest
from src.dependency_searchers.package_parsers import ConanParser


class TestConanParser(unittest.TestCase):

    def test_parse_valid_conan_file(self):
        conan_valid_data = """
from conans import CMake, ConanFile, tools
import os


class CerealConan(ConanFile):
name="cereal"
version="v1.1.2"
author="John Doe (john.doe@email.com)"
description="Serialization header-only library for C++11."
license="BSD-3"
url="https://github.com/USCiLab/cereal.git"
generators="cmake"
settings="os"
exports_sources="src/*", "CMakeLists.txt"
revision_mode="scm"

options={
    "fPIC": [True, False],
    "shared": [True, False]
}
default_options={
    "fPIC": True,
    "shared": True
}

def build(self):
    cmake=CMake(self)

    cmake.definitions["SKIP_PORTABILITY_TEST"]="OFF"
    cmake.definitions["USE_BOOST"]="OFF"
    self.output.info(cmake.definitions)

    cmake.configure()
    cmake.build()

def package(self):
    self.copy("*.h", src="src/include", dst="include")
    self.copy("*.hpp", src="src/include", dst="include")
    self.copy("*.txt", src="src/include", dst="include")
    self.copy("*.html", src="src/include", dst="include")
    self.copy("*LICENSE*", src="src", dst="licenses")

def package_id(self):
    self.info.header_only()"""

        dependencies = ConanParser().parse(conan_valid_data)

        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'cereal')
        self.assertEqual(dependencies[0]['Version'], 'v1.1.2')
        self.assertEqual(dependencies[0]['License'], 'BSD-3')


if __name__ == '__main__':
    unittest.main()
