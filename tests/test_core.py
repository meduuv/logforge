import unittest

from logforge.core import analyze, parse


class LogForgeTests(unittest.TestCase):
    def test_repeated_failed_auth_is_flagged(self):
        lines = [
            "sshd: Failed password for root from 1.2.3.4 port 22 ssh2"
        ] * 5
        events = parse(lines)
        report = analyze(events, threshold=5)
        self.assertEqual(report["suspicious_sources"][0]["ip"], "1.2.3.4")
        self.assertEqual(report["suspicious_sources"][0]["failures"], 5)

    def test_successful_auth_is_parsed(self):
        events = parse(
            ["Accepted publickey for medu from 1.2.3.4 port 22 ssh2"]
        )
        self.assertEqual(events[0].kind, "successful_auth")
        self.assertEqual(events[0].user, "medu")

    def test_unknown_lines_are_ignored(self):
        self.assertEqual(parse(["kernel: service started"]), [])

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze([], threshold=0)


if __name__ == "__main__":
    unittest.main()
