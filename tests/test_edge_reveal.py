import tempfile
import unittest
from io import StringIO
from pathlib import Path

from EdgeReveal import EdgeReveal, ReportWriter, ResolveResult, ScanReport


class EdgeRevealTests(unittest.TestCase):
    def test_default_wordlist_uses_bundled_subdomains_file(self):
        scanner = EdgeReveal("example.com", wordlists=[], quiet=True)

        wordlist_path = Path(scanner.wordlists[0])
        self.assertEqual(wordlist_path.name, "subdomains.txt")
        self.assertTrue(wordlist_path.exists())

    def test_load_wordlists_skips_comments_lowercases_and_dedupes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wordlist = Path(tmpdir) / "custom.txt"
            wordlist.write_text(
                "# comment\nWWW\napi\nwww\n\nMail\n",
                encoding="utf-8",
            )

            scanner = EdgeReveal("example.com", wordlists=[str(wordlist)], quiet=True)

            self.assertEqual(scanner.load_wordlists(), ["api", "mail", "www"])

    def test_normal_report_can_include_only_found_results(self):
        report = ScanReport(target_domain="example.com")
        report.total_checked = 2
        report.found.append(
            ResolveResult(
                domain="mail.example.com",
                ipv4=["192.0.2.10"],
                status="found",
            )
        )
        report.not_found.append(
            ResolveResult(domain="missing.example.com", status="not_found")
        )

        output = StringIO()
        ReportWriter._write_normal(report, output, only_found=True)
        rendered = output.getvalue()

        self.assertIn("EdgeReveal Scan Report", rendered)
        self.assertIn("mail.example.com", rendered)
        self.assertNotIn("missing.example.com", rendered)


if __name__ == "__main__":
    unittest.main()
