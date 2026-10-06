import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend"))

from detector import analyze_log

def test_sqli_detection():
    res = analyze_log("198.51.100.1", "payment-service", "GET /users?id=1' UNION SELECT * FROM admin--")
    assert res is not None
    assert res["severity"] == "CRITICAL"
    assert "SQL Injection" in res["category"]
    print("[PASS] SQL Injection test passed.")

def test_xss_detection():
    res = analyze_log("192.0.2.1", "web-frontend", "POST /comment <script>alert(1)</script>")
    assert res is not None
    assert res["severity"] == "HIGH"
    assert "XSS" in res["category"]
    print("[PASS] XSS test passed.")

def test_path_traversal_detection():
    res = analyze_log("198.51.100.2", "file-server", "GET /view?file=../../../../etc/passwd")
    assert res is not None
    assert res["severity"] == "CRITICAL"
    assert "Path Traversal" in res["category"]
    print("[PASS] Path Traversal test passed.")

if __name__ == "__main__":
    test_sqli_detection()
    test_xss_detection()
    test_path_traversal_detection()
    print("\n[SUCCESS] ALL UNIT TESTS PASSED SUCCESSFULLY!")
