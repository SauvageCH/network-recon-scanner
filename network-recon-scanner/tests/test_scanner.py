import unittest

from scanner import parser, validators, vuln_checks

SAMPLE_XML = """<nmaprun scanner="nmap" args="nmap -sV 10.0.0.5" version="7.94">
<host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="lab.local"/></hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
<port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
</ports></host></nmaprun>"""


class ValidatorTests(unittest.TestCase):
    def test_private_ok(self):
        self.assertEqual(validators.validate_target("192.168.1.10"), "192.168.1.10/32")

    def test_public_blocked(self):
        with self.assertRaises(ValueError):
            validators.validate_target("8.8.8.8")

    def test_injection_blocked(self):
        with self.assertRaises(ValueError):
            validators.validate_target("127.0.0.1; rm -rf /")

    def test_too_big(self):
        with self.assertRaises(ValueError):
            validators.validate_target("10.0.0.0/8")

    def test_scanme_allowed(self):
        self.assertEqual(validators.validate_target("scanme.nmap.org"), "scanme.nmap.org")


class ParserAndAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.result = parser.parse_xml(SAMPLE_XML)

    def test_parse(self):
        h = self.result["hosts"][0]
        self.assertEqual(h["ip"], "10.0.0.5")
        self.assertEqual(len(h["ports"]), 3)

    def test_findings(self):
        titles = [f["title"] for f in vuln_checks.analyze(self.result)]
        self.assertTrue(any("SMB" in t for t in titles))
        self.assertTrue(any("vsftpd" in t for t in titles))

    def test_summary(self):
        f = vuln_checks.analyze(self.result)
        s = vuln_checks.summarize(self.result, f)
        self.assertEqual(s["open_ports"], 2)
        self.assertGreaterEqual(s["severity"]["high"], 2)


if __name__ == "__main__":
    unittest.main()
