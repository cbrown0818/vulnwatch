import unittest

import vulnwatch


class VulnWatchTests(unittest.TestCase):
    def test_platform_detection_separates_apple_mobile(self):
        cve = {"descriptions": [{"lang": "en", "value": "Apple iOS and iPadOS before 18 are affected"}]}
        self.assertEqual(vulnwatch.detect_platforms(cve), ["iOS/iPadOS"])

    def test_platform_detection_from_cpe(self):
        cve = {"configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"}]}]}]}
        self.assertEqual(vulnwatch.detect_platforms(cve), ["Windows"])

    def test_kev_is_prioritized(self):
        newer = vulnwatch.risk_score(9.0, 0.2, False, False, "2026-07-01T00:00:00Z")
        exploited = vulnwatch.risk_score(7.0, 0.2, True, False, "2026-07-01T00:00:00Z")
        self.assertGreater(exploited, newer)

    def test_risk_score_accepts_nvd_timestamp_without_timezone(self):
        score = vulnwatch.risk_score(8.0, 0.5, False, False, "2026-07-01T12:30:00.000")
        self.assertIsInstance(score, float)
        self.assertGreater(score, 0)


if __name__ == "__main__":
    unittest.main()
