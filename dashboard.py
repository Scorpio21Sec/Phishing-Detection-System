#!/usr/bin/env python3
"""Small local web dashboard for interactive phishing checks."""

import json
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from phishing_detector import PhishingDetector

HOST = "127.0.0.1"
PORT = 8000

PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signal Desk | Phishing Detection</title>
<style>
:root { --ink:#18232b; --muted:#64727b; --paper:#f5f3ee; --panel:#fffdf9; --line:#dedbd2; --teal:#087f78; --red:#c94b43; --amber:#c58228; --green:#2b8061; }
* { box-sizing:border-box; }
body { margin:0; color:var(--ink); background:radial-gradient(circle at 10% 0%, #d9eee9 0, transparent 33%), var(--paper); font:16px/1.5 Georgia, serif; }
.shell { max-width:1180px; margin:0 auto; padding:42px 24px 60px; }
header { display:flex; justify-content:space-between; align-items:end; gap:24px; margin-bottom:34px; }
.eyebrow { color:var(--teal); font:700 12px/1.2 system-ui,sans-serif; letter-spacing:.12em; text-transform:uppercase; }
h1 { margin:8px 0 0; font-size:clamp(2.3rem, 6vw, 4.8rem); line-height:.95; letter-spacing:-.04em; font-weight:700; }
.status { border:1px solid var(--line); border-radius:999px; padding:8px 13px; color:var(--muted); background:rgba(255,253,249,.7); font:600 12px system-ui,sans-serif; white-space:nowrap; }
.grid { display:grid; grid-template-columns:minmax(0,1.05fr) minmax(320px,.95fr); gap:20px; align-items:start; }
.panel { background:rgba(255,253,249,.9); border:1px solid var(--line); box-shadow:0 18px 45px rgba(35,57,55,.07); border-radius:8px; padding:25px; }
.panel h2 { margin:0 0 5px; font-size:1.45rem; }
.sub { color:var(--muted); margin:0 0 22px; }
.tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin:0 -25px 21px; padding:0 25px; }
.tab { border:0; border-bottom:3px solid transparent; background:none; color:var(--muted); cursor:pointer; padding:11px 5px; margin-right:18px; font:700 13px system-ui,sans-serif; }
.tab.active { color:var(--teal); border-color:var(--teal); }
label { display:block; color:var(--muted); font:700 11px system-ui,sans-serif; letter-spacing:.08em; text-transform:uppercase; margin:15px 0 7px; }
input, textarea { width:100%; border:1px solid #c8c8c0; border-radius:5px; background:#fff; color:var(--ink); padding:12px 13px; font:16px Georgia,serif; }
textarea { min-height:146px; resize:vertical; }
button.primary { border:0; border-radius:5px; background:var(--teal); color:#fff; cursor:pointer; padding:12px 17px; font:700 14px system-ui,sans-serif; }
button.primary:hover { background:#066861; }
.samples { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
.sample { border:1px solid var(--line); border-radius:999px; background:transparent; color:var(--muted); cursor:pointer; padding:7px 10px; font:12px system-ui,sans-serif; }
.sample:hover { border-color:var(--teal); color:var(--teal); }
#result { min-height:320px; }
.empty { color:var(--muted); display:grid; place-items:center; min-height:275px; text-align:center; }
.result-head { display:flex; justify-content:space-between; align-items:start; gap:15px; border-bottom:1px solid var(--line); padding-bottom:18px; }
.result-head h2 { font-size:1.9rem; text-transform:capitalize; }
.score { font:700 2.8rem/1 system-ui,sans-serif; color:var(--teal); }
.score small { color:var(--muted); font-size:12px; font-weight:500; }
.meter { height:9px; background:#e7e4dc; border-radius:99px; overflow:hidden; margin:18px 0; }
.meter span { display:block; height:100%; background:var(--teal); border-radius:inherit; transition:width .4s ease; }
.meta { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin:18px 0; }
.meta div { background:#f2f0e9; border-radius:5px; padding:10px 12px; color:var(--muted); font:12px system-ui,sans-serif; }
.meta strong { display:block; color:var(--ink); font-size:15px; margin-top:3px; }
ul { padding-left:20px; margin-bottom:0; } li { margin:8px 0; }
.error { color:var(--red); font-family:system-ui,sans-serif; }
.hidden { display:none; }
@media (max-width:760px) { .shell { padding:25px 14px 40px; } header { display:block; } .status { display:inline-block; margin-top:18px; } .grid { grid-template-columns:1fr; } .panel { padding:20px; } .tabs { margin-left:-20px; margin-right:-20px; padding:0 20px; } }
</style>
</head>
<body>
<main class="shell">
<header><div><div class="eyebrow">Local security workspace</div><h1>Signal Desk</h1></div><div class="status">RULES + ML &nbsp;·&nbsp; OFFLINE READY</div></header>
<section class="grid">
<div class="panel">
<h2>Inspect a signal</h2><p class="sub">Run a transparent triage check against a URL or email.</p>
<div class="tabs"><button class="tab active" data-mode="url">URL check</button><button class="tab" data-mode="email">Email check</button></div>
<form id="check-form">
<div id="url-fields"><label for="url">URL</label><input id="url" value="http://secure-paypal-login.xyz/verify-account" autocomplete="off"></div>
<div id="email-fields" class="hidden"><label for="from_addr">From address</label><input id="from_addr" placeholder="PayPal Support &lt;security@example.com&gt;"><label for="subject">Subject</label><input id="subject" placeholder="Urgent: verify your account"><label for="body">Message body</label><textarea id="body" placeholder="Paste the message body here..."></textarea><label for="return_path">Return-Path</label><input id="return_path" placeholder="bounce@another-domain.example"></div>
<div style="margin-top:19px"><button class="primary" type="submit">Analyze signal</button></div>
</form>
<div class="samples"><button class="sample" data-url="https://www.google.com/search?q=weather">Safe sample</button><button class="sample" data-url="http://192.168.1.5/paypal/login.php">IP host sample</button><button class="sample" data-url="http://bit.ly/3xK9pL2">Short link sample</button></div>
</div>
<div class="panel" id="result"><div class="empty">Your assessment will appear here.<br>Start with a URL or email.</div></div>
</section>
</main>
<script>
let mode = 'url';
const $ = (id) => document.getElementById(id);
const tabs = document.querySelectorAll('.tab');
tabs.forEach(tab => tab.addEventListener('click', () => { mode = tab.dataset.mode; tabs.forEach(item => item.classList.toggle('active', item === tab)); $('url-fields').classList.toggle('hidden', mode !== 'url'); $('email-fields').classList.toggle('hidden', mode !== 'email'); }));
document.querySelectorAll('.sample').forEach(button => button.addEventListener('click', () => { mode = 'url'; tabs.forEach(item => item.classList.toggle('active', item.dataset.mode === mode)); $('url-fields').classList.remove('hidden'); $('email-fields').classList.add('hidden'); $('url').value = button.dataset.url; $('check-form').requestSubmit(); }));
$('check-form').addEventListener('submit', async (event) => { event.preventDefault(); $('result').innerHTML = '<div class="empty">Analyzing...</div>'; const payload = mode === 'url' ? {url:$('url').value} : {from_addr:$('from_addr').value, subject:$('subject').value, body:$('body').value, return_path:$('return_path').value}; try { const response = await fetch('/api/check', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({mode, ...payload})}); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Request failed'); render(data); } catch (error) { $('result').innerHTML = `<div class="empty error">${error.message}</div>`; } });
function render(data) { const score = Math.round(data.score); const reasons = data.reasons.length ? `<ul>${data.reasons.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>` : '<p>No rule signals were triggered.</p>'; $('result').innerHTML = `<div class="result-head"><div><div class="eyebrow">${data.input_type} assessment</div><h2>${data.verdict.replace('_',' ')}</h2></div><div class="score">${score}<small>/100</small></div></div><div class="meter"><span style="width:${score}%"></span></div><div class="meta"><div>Rule score<strong>${data.rule_score}/100</strong></div><div>ML probability<strong>${data.ml_probability === null ? 'Not used' : `${(data.ml_probability * 100).toFixed(1)}%`}</strong></div></div><div><div class="eyebrow">Why it was flagged</div>${reasons}</div>`; }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[char])); }
</script>
</body>
</html>'''


class DashboardHandler(BaseHTTPRequestHandler):
    detector = PhishingDetector()

    def _send_json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path != "/":
            self._send_json({"error": "Not found"}, 404)
            return
        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/check":
            self._send_json({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            request = json.loads(self.rfile.read(length))
            if request.get("mode") == "url":
                value = request.get("url", "").strip()
                if not value:
                    raise ValueError("Enter a URL to analyze")
                result = self.detector.check_url(value)
            elif request.get("mode") == "email":
                result = self.detector.check_email({key: request.get(key, "") for key in ("from_addr", "subject", "body", "return_path")})
            else:
                raise ValueError("Unsupported check mode")
            self._send_json({"input_type": result.input_type, "score": result.score, "verdict": result.verdict, "rule_score": result.rule_score, "ml_probability": result.ml_probability, "reasons": result.reasons})
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json({"error": str(error)}, 400)

    def log_message(self, format, *args):
        print(f"dashboard: {args[0]}")


def main():
    parser = argparse.ArgumentParser(description="Run the local phishing detection dashboard")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Signal Desk running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
