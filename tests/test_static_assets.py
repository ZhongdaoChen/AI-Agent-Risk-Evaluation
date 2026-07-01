import unittest

from fastapi.testclient import TestClient

from main import app


class StaticAssetTests(unittest.TestCase):
    def test_report_exporter_javascript_is_served(self):
        client = TestClient(app)

        response = client.get("/static/report_exporter.js")

        self.assertEqual(response.status_code, 200)
        self.assertIn("ReportExporter", response.text)
        self.assertIn("buildHtmlReport", response.text)


if __name__ == "__main__":
    unittest.main()
