from __future__ import annotations

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


class VersionContractTests(unittest.TestCase):
    def test_one_source_version_drives_app_and_package_scripts(self) -> None:
        props = ET.parse(ROOT / "Directory.Build.props").getroot()
        values = [
            node.text.strip()
            for node in props.findall(".//Version")
            if node.text and node.text.strip()
        ]
        self.assertEqual(1, len(values))
        version = values[0]
        self.assertRegex(version, r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")

        view_model = (
            ROOT
            / "src/CrossPlatform/SupertonicVox.Desktop/MainWindowViewModel.cs"
        ).read_text(encoding="utf-8")
        self.assertIn("AssemblyInformationalVersionAttribute", view_model)
        self.assertNotIn('AppVersion = "0.1.0', view_model)

        mac_script = (ROOT / "packaging/build-macos-release.sh").read_text(encoding="utf-8")
        windows_script = (ROOT / "packaging/build-windows-release.ps1").read_text(encoding="utf-8")
        for script in (mac_script, windows_script):
            self.assertIn("Directory.Build.props", script)
            self.assertIn("PackageVersion", script.replace("PACKAGE_VERSION", "PackageVersion"))
        self.assertNotRegex(mac_script, re.compile(r"PACKAGE_VERSION=.*0\.1\.0"))
        self.assertNotRegex(windows_script, re.compile(r"PackageVersion.*0\.1\.0"))

        source_version_position = windows_script.index("$SourceVersion =")
        default_resolution_position = windows_script.index("if (-not $PackageVersion)")
        version_validation_position = windows_script.index("if ($PackageVersion -notmatch")
        equality_check_position = windows_script.index("if ($PackageVersion -ne $SourceVersion)")
        self.assertLess(source_version_position, default_resolution_position)
        self.assertLess(default_resolution_position, version_validation_position)
        self.assertLess(version_validation_position, equality_check_position)
        default_block = windows_script[
            default_resolution_position:version_validation_position
        ]
        self.assertIn("$env:SVX_PACKAGE_VERSION", default_block)
        self.assertIn("$SourceVersion", default_block)

        info = ET.parse(ROOT / "packaging/macos/Info.plist").getroot()
        strings = [node.text for node in info.iter("string")]
        self.assertIn(version, strings)


if __name__ == "__main__":
    unittest.main()
