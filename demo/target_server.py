"""
靶机 HTTP 服务 —— 模拟有漏洞的 Web 应用

监听 0.0.0.0:8080，提供以下端点供攻击脚本测试：
  GET  /login.php     — 模拟 SQL 注入入口（回显查询参数）
  GET  /search         — 模拟搜索框（回显搜索词，XSS 入口）
  GET  /comment        — 模拟评论功能（回显内容，XSS 入口）
  GET  /download       — 模拟文件下载（回显路径，路径遍历入口）
  GET  /ping           — 模拟网络诊断（回显参数，命令注入入口）
  GET  /cgi-bin/status — 模拟 CGI 状态页（命令注入入口）
  POST /api/xml        — 模拟 XML 接口（XXE 入口）
  GET  /upload.php     — 模拟上传接口（Webshell 入口）
  GET  /faxsurvey      — 模拟传真调查（木马入口）

用法:  sudo python demo/target_server.py
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HOST = "0.0.0.0"
PORT = 8080


class VulnerableHandler(BaseHTTPRequestHandler):
    """有漏洞的请求处理器 —— 回显用户输入，不做任何过滤。"""

    def log_message(self, fmt, *args):
        print(f"[靶机] {args[0]}")

    def _send(self, body: str, status: int = 200, content_type: str = "text/html; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/login.php":
            uid = qs.get("id", ["unknown"])[0]
            self._send(f"<h1>Login</h1><p>User ID: {uid}</p><p>Query executed.</p>")

        elif path == "/search":
            q = qs.get("q", [""])[0]
            self._send(f"<h1>Search Results</h1><p>Results for: {q}</p>")

        elif path == "/comment":
            text = qs.get("text", [""])[0]
            self._send(f"<h1>Comments</h1><div>{text}</div>")

        elif path == "/download":
            f = qs.get("file", [""])[0]
            self._send(f"<h1>Download</h1><p>Requested file: {f}</p><p>File not found.</p>")

        elif path == "/ping":
            host = qs.get("host", ["127.0.0.1"])[0]
            self._send(f"<h1>Ping</h1><p>Pinging {host}...</p><p>4 packets transmitted, 4 received.</p>")

        elif path == "/cgi-bin/status":
            cmd = qs.get("cmd", [""])[0]
            self._send(f"<h1>Status</h1><p>Command: {cmd}</p><p>Output: OK</p>")

        elif path == "/faxsurvey":
            self._send("<h1>Fax Survey</h1><p>Please enter your fax number.</p>")

        elif path == "/upload.php":
            self._send("<h1>Upload</h1><p>File upload page.</p>")

        elif path == "/redirect":
            url = qs.get("url", [""])[0]
            self._send(f"<h1>Redirect</h1><p>Redirecting to: {url}</p>")

        elif path == "/admin/exec":
            cmd = qs.get("cmd", [""])[0]
            self._send(f"<h1>Admin Exec</h1><p>cmd: {cmd}</p>")

        elif path == "/item":
            item_id = qs.get("id", ["0"])[0]
            self._send(f"<h1>Item {item_id}</h1><p>Item details here.</p>")

        elif path == "/report":
            sort = qs.get("sort", ["id"])[0]
            self._send(f"<h1>Report</h1><p>Sorted by: {sort}</p>")

        elif path == "/page":
            name = qs.get("name", [""])[0]
            self._send(f"<h1>Page</h1><p>Welcome, {name}!</p>")

        elif path == "/product.php":
            pid = qs.get("id", ["0"])[0]
            self._send(f"<h1>Product {pid}</h1><p>Details...</p>")

        elif path == "/profile":
            self._send("<h1>Profile</h1><p>Update your profile here.</p>")

        elif path == "/feedback":
            self._send("<h1>Feedback</h1><p>Submit your feedback.</p>")

        elif path == "/api/users":
            self._send(json.dumps({"users": [{"id": 1, "name": "admin"}]}),
                       content_type="application/json")

        elif path == "/api/export":
            p = qs.get("path", [""])[0]
            self._send(json.dumps({"status": "ok", "path": p}),
                       content_type="application/json")

        elif path == "/api/search":
            q = qs.get("q", [""])[0]
            self._send(json.dumps({"results": [], "query": q}),
                       content_type="application/json")

        elif path == "/":
            self._send("""<h1>Vulnerable Test Server</h1>
            <p>Available endpoints:</p>
            <ul>
            <li>/login.php?id=</li>
            <li>/search?q=</li>
            <li>/comment?text=</li>
            <li>/download?file=</li>
            <li>/ping?host=</li>
            <li>/cgi-bin/status?cmd=</li>
            <li>/faxsurvey</li>
            <li>/upload.php</li>
            <li>/redirect?url=</li>
            <li>/admin/exec?cmd=</li>
            <li>/item?id=</li>
            <li>/report?sort=</li>
            <li>/page?name=</li>
            <li>/product.php?id=</li>
            <li>/api/export?path=</li>
            <li>/api/search?q=</li>
            </ul>""")
        else:
            self._send(f"<h1>404 Not Found</h1><p>Path: {path}</p>", status=404)

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="replace") if content_len else ""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/query":
            self._send(f"<h1>Query Result</h1><pre>{body}</pre>")

        elif path == "/api/login":
            self._send(f"<h1>Login Result</h1><pre>{body}</pre>")

        elif path == "/login":
            self._send(f"<h1>Login</h1><pre>{body}</pre>")

        elif path == "/profile":
            self._send(f"<h1>Profile Updated</h1><pre>{body}</pre>")

        elif path == "/feedback":
            self._send(f"<h1>Feedback Received</h1><pre>{body}</pre>")

        elif path == "/upload":
            self._send(f"<h1>Upload</h1><pre>{body}</pre>")

        elif path == "/api/xml":
            self._send(f"<h1>XML Received</h1><pre>{body}</pre>", content_type="application/xml")

        elif path == "/soap":
            self._send(f"<h1>SOAP Received</h1><pre>{body}</pre>", content_type="application/xml")

        elif path == "/exec":
            self._send(f"<h1>Exec</h1><pre>{body}</pre>")

        elif path == "/api/editor.php":
            self._send(f"<h1>Editor</h1><pre>{body}</pre>")

        else:
            self._send(f"<h1>404</h1><pre>{body}</pre>", status=404)


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), VulnerableHandler)
    print(f"[靶机] 有漏洞的 Web 服务已启动: http://{HOST}:{PORT}")
    print(f"[靶机] 可用端点见 http://{HOST}:{PORT}/")
    print(f"[靶机] 按 Ctrl+C 停止")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[靶机] 服务已停止")
        server.shutdown()
