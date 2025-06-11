import unittest
from src.dependency_searchers.package_parsers import BazelParser


class TestBazelParser(unittest.TestCase):

    def test_parse_valid_bazel_file_no_discernable_version(self):
        bazel_data_no_discernable_version = """
\"\"\" module to load OpenSSL library \"\"\"

load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")

def load_OpenSSL_repo():
    http_archive(
        name = \"OpenSSL\",
        build_file = \"@third_party_binaries//OpenSSL:OpenSSL.BUILD\",
        sha256 = \"90eed3f76fabd51b2060852b0d65415ef3adece344f23e490e3c3416dceaedbd\",
        urls = [
            \"https://registry.ci.motional.com:443/artifactory/conan/av/OpenSSL/1.1.1k/stable/29db8241d8f8f516989667dd40fe1140e3625dd7/package/dd0667184dd0fae4e8289bf8b9f585c67e02f857/172b7e6591415172867e4bb13d304367/conan_package.tgz\",
        ],
    )
        """

        dependencies = BazelParser().parse(bazel_data_no_discernable_version)

        self.assertEqual(len(dependencies), 0)

    def test_parse_valid_bazel_file_dash_version(self):
        bazel_data_dash_version = """
\"\"\" module to load asio library \"\"\"

load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")

def load_asio_repo():
    http_archive(
        name = \"asio\",
        build_file = \"@//third_party/asio:asio.BUILD\",
        sha256 = \"fa8c3a16dc2163f5b3451f2a14ce95277c971f46700497d4e94af6059c00dc06\",
        strip_prefix = \"asio-1-12-0\",
        urls = [
            \"https://registry.ci.motional.com:443/artifactory/internet-resources/github.com/chriskohlhoff/asio/archive/asio-1-12-0.tar.gz\",
            \"https://github.com/chriskohlhoff/asio/archive/asio-1-12-0.tar.gz\",
        ],
    )
    	"""

        dependencies = BazelParser().parse(bazel_data_dash_version)

        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'asio')
        self.assertEqual(dependencies[0]['Version'], '1')
        self.assertEqual(dependencies[0]['License'], 'Boost Software License 1.0')

    def test_parse_valid_bazel_file_dot_version(self):
        bazel_data_dot_version = """
\"\"\" module to load KTX library \"\"\"

load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")

def load_KTX_repo():
    http_archive(
        # conan KTX/4.0.0-Beta3@av/stable
        name = \"KTX\",
        build_file = \"@third_party_binaries//KTX:KTX.BUILD\",
        sha256 = \"3113c5c4a423b3455a1e03bda18fc647f9c09c7018a773a7d96a917fec1db4cd\",
        strip_prefix = \"7cddc4f639fa33912f84cca0843c1e12205f2f24\",
        urls = [
            \"https://registry.ci.motional.com:443/artifactory/internet-resources/conan/tarball/KTX-4.0.0-Beta3-latest.tgz\",
        ],
    )
        """

        dependencies = BazelParser().parse(bazel_data_dot_version)

        self.assertEqual(len(dependencies), 1)

        self.assertEqual(dependencies[0]['ModuleName'], 'KTX')
        self.assertEqual(dependencies[0]['Version'], '4.0.0')
        self.assertEqual(dependencies[0]['License'], 'Apache 2.0')

    def test_parse_valid_bazel_file_two_dependencies(self):
        bazel_data_two_dependencies = """
    maybe(
        http_archive,
        name = "rules_python",
        sha256 = "9acc0944c94adb23fba1c9988b48768b1bacc6583b52a2586895c5b7491e2e31",
        strip_prefix = "rules_python-0.27.0",
        url = "https://registry.ci.fake.com/repository/github/bazelbuild/rules_python/archive/refs/tags/0.27.0.tar.gz",
    )

    maybe(
        http_archive,
        name = "fmt",
        sha256 = "5dea48d1fcddc3ec571ce2058e13910a0d4a6bab4cc09a809d8b1dd1c88ae6f2",
        strip_prefix = "fmt-9.1.0",
        url = "https://registry.ci.fake.com/repository/github/fmtlib/fmt/archive/9.1.0.tar.gz",
    )
        """
        
        dependencies = BazelParser().parse(bazel_data_two_dependencies)

        self.assertEqual(len(dependencies), 2)

        self.assertEqual(dependencies[0]['ModuleName'], 'rules_python')
        self.assertEqual(dependencies[0]['Version'], '0.27.0')
        
        self.assertEqual(dependencies[1]['ModuleName'], 'fmt')
        self.assertEqual(dependencies[1]['Version'], '9.1.0')

if __name__ == '__main__':
    unittest.main()
