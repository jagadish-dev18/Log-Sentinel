import unittest
from analyzer.log_analyzer import analyze_lines, parse_line


class ParserTests(unittest.TestCase):
    def test_key_value_failed_login(self):
        event = parse_line("2026-10-12 08:14:33 FAILED_LOGIN user=admin ip=192.0.2.44", 1)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed")
        self.assertEqual(event.username, "admin")
        self.assertEqual(event.source_ip, "192.0.2.44")

    def test_ssh_failed_login(self):
        event = parse_line("Oct 12 10:13:45 lab-host sshd[2241]: Failed password for invalid user test from 192.0.2.44 port 53812 ssh2", 1)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed")
        self.assertEqual(event.source_ip, "192.0.2.44")

    def test_ssh_success_login(self):
        event = parse_line("Oct 12 10:15:06 lab-host sshd[2248]: Accepted password for analyst from 192.0.2.18 port 53821 ssh2", 1)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "success")
        self.assertEqual(event.username, "analyst")

    def test_json_login_event(self):
        event = parse_line('{"timestamp":"2026-10-12T09:00:00Z","event":"failed_login","username":"root","ip":"198.51.100.8"}', 1)
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed")
        self.assertEqual(event.source_ip, "198.51.100.8")

    def test_unknown_line_is_not_parsed(self):
        self.assertIsNone(parse_line("This line has no known authentication structure", 1))

    def test_threshold_flags_ip(self):
        lines = [f"2026-10-12 08:0{i}:00 FAILED_LOGIN user=admin ip=192.0.2.44" for i in range(1, 6)]
        events, unparsed, stats = analyze_lines(lines, threshold=5)
        self.assertEqual(len(events), 5)
        self.assertEqual(unparsed, [])
        self.assertTrue(stats["192.0.2.44"]["flagged"])

    def test_below_threshold_is_not_flagged(self):
        lines = ["2026-10-12 08:01:00 FAILED_LOGIN user=admin ip=192.0.2.44"]
        _, _, stats = analyze_lines(lines, threshold=5)
        self.assertFalse(stats["192.0.2.44"]["flagged"])

    def test_unparsed_lines_are_counted(self):
        events, unparsed, _ = analyze_lines(["not a log line"], threshold=5)
        self.assertEqual(events, [])
        self.assertEqual(len(unparsed), 1)


if __name__ == "__main__":
    unittest.main()
