"""Opt-in browser QA against a running dashboard; API fixtures never modify its data.

Install Playwright separately. CRYPTODEP_TEST_BROWSER optionally selects an installed browser.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import expect, sync_playwright

from cryptodep.web.risk import annotate_risks


def main(url):
    root = Path(__file__).resolve().parents[2]
    document = json.loads((root / "examples/dvja_cdg_example.json").read_text())
    document["nodes"] += [
        {"node_id": "qa:sha1", "node_type": "CryptoAlgorithm", "label": "SHA-1", "algorithm_family": "SHA-1", "quantum_vuln_class": "quantum_safe_symmetric"},
        {"node_id": "qa:aes", "node_type": "CryptoAlgorithm", "label": "AES-128-GCM", "algorithm_family": "AES", "quantum_vuln_class": "grover_weakened"},
        {"node_id": "qa:unknown", "node_type": "CryptoAlgorithm", "label": "CustomCipher", "algorithm_family": "CUSTOM", "quantum_vuln_class": "unknown"},
        {"node_id": "qa:controller", "node_type": "AppComponent", "label": "LoginController"},
    ]
    component = next(node for node in document["nodes"] if node["node_type"] == "AppComponent")
    library = next(node for node in document["nodes"] if node["node_type"] == "CryptoLibrary")
    document["edges"] += [
        {"source_id": "qa:controller", "target_id": component["node_id"], "edge_type": "depends_on", "confidence": .8},
        {"source_id": library["node_id"], "target_id": "qa:sha1", "edge_type": "implements", "confidence": .9},
    ]
    annotate_risks(document)
    scan = {"id": "00000000-0000-4000-8000-000000000001", "repo_url": "https://github.com/appsecco/dvja", "status": "completed",
            "created_at": "2026-11-04T00:00:00Z", "model": "visual-fixture", "progress": {}, "summary": {}, "error": None}

    def mock_api(route):
        path = urlsplit(route.request.url).path
        if path == "/api/settings":
            data = {"endpoint": "", "model": "", "has_key": False}
        elif path == "/api/scans":
            data = [scan]
        elif path == f"/api/scans/{scan['id']}/graph":
            data = document
        elif path == f"/api/scans/{scan['id']}/questions":
            data = []
        elif path == f"/api/scans/{scan['id']}/log":
            data = {"lines": ["[info ] ingestion_start", "[warning ] semgrep_partial_errors count=1"]}
        else:
            raise AssertionError("Unexpected API request: " + path)
        route.fulfill(json=data)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.getenv("CRYPTODEP_TEST_BROWSER") or None, headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1100})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/api/**", mock_api)
        page.goto(url, wait_until="networkidle")
        # The dashboard starts empty; open the scan from history.
        expect(page.locator("#repo-url")).to_be_enabled()
        page.locator("#history-open").click()
        page.locator(".history-item").first.click()
        expect(page.locator("#node-count")).to_have_text("10")
        expect(page.locator("#repo-url")).to_be_disabled()
        assert page.evaluate("graph.nodes('[type=\"PQCAlgorithm\"]').first().style('shape')") == "round-diamond"
        page.locator("#log-toggle").click()
        expect(page.locator("#log-lines .log-warn")).to_contain_text("semgrep_partial_errors")
        page.locator("#log-close").click()
        expect(page.locator("#scan-log")).to_be_hidden()
        assert page.evaluate("graph.nodes('[risk=\"orange\"]').length") == 3
        assert page.evaluate("graph.nodes('[risk=\"unknown\"]').length") == 1
        page.get_by_role("tab", name="Daftar", exact=True).click()
        page.get_by_role("button", name="MD5", exact=True).click()
        expect(page.locator("#detail-body")).to_contain_text("collision klasik")
        expect(page.locator("#detail-body")).to_contain_text("Argon2id")
        page.get_by_role("button", name="Tutup detail node").click()
        page.locator(".graph-options summary").click()
        page.select_option("#risk-filter", "orange")
        assert page.locator("#node-list tr").count() == 3
        page.select_option("#risk-filter", "all")
        page.locator(".graph-options summary").click()
        page.get_by_role("tab", name="Graph", exact=True).click()
        page.locator("#graph").scroll_into_view_if_needed()
        box = page.locator("#graph").bounding_box()
        page.wait_for_timeout(1500)  # let the animated layout settle before clicking a node position
        point = page.evaluate("graph.nodes('[risk=\"red\"]').first().renderedPosition()")
        page.mouse.dblclick(box["x"] + point["x"], box["y"] + point["y"], delay=80)
        expect(page.locator("#local-graph")).to_have_attribute("aria-pressed", "true")
        assert page.evaluate("graph.nodes(':visible').length") == 4
        page.locator(".graph-options summary").click()
        page.locator("#local-depth").fill("2")
        page.locator("#local-depth").dispatch_event("change")
        assert page.evaluate("graph.nodes(':visible').length") == 6
        page.locator(".graph-options summary").click()
        page.locator("#local-graph").click()
        page.get_by_role("button", name="Sematkan posisi").click()
        pinned = page.evaluate("graph.nodes(':locked').first().position()")
        page.locator("#relayout-graph").click()
        page.wait_for_timeout(600)
        assert page.evaluate("graph.nodes(':locked').first().position()") == pinned
        page.locator("#node-search").fill("CustomCipher")
        assert page.evaluate("graph.nodes(':visible').length") == 1
        page.locator("#node-search").fill("")
        page.evaluate("graph.nodes().first().emit('mouseover')")
        assert page.evaluate("graph.elements('.hover-fade').length") > 0
        page.evaluate("graph.nodes().first().emit('mouseout'); graph.edges().first().emit('tap')")
        expect(page.locator("#detail-body")).to_contain_text("Bukti hubungan")
        page.locator("#detail-close").click()
        page.locator("#fullscreen-graph").click()
        assert page.evaluate("Boolean(document.fullscreenElement)")
        page.evaluate("document.exitFullscreen()")
        page.set_viewport_size({"width": 390, "height": 844})
        page.wait_for_timeout(250)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        assert not errors, errors
        browser.close()
    print("PASS: risk warnings/colors, list filters, double-click, local depth, pinning, search, hover, edge details, fullscreen, mobile")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8088")
    main(parser.parse_args().url)
