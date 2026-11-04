"""Minimal Chrome DevTools Protocol driver for checking the web UI without a browser extension.

Usage: bbot/.venv/bin/python tools/cdp_drive.py http://127.0.0.1:8777/ steps.json
steps.json is a list of JS expressions (evaluated in the page, promises awaited) and numbers (sleep, seconds).
Each step prints the first 90 characters of the expression, " => " and the returned value; JS exceptions
and console messages are printed too. Starts its own headless Chrome on port 9333 with a temporary profile.
"""
import asyncio, json, subprocess, sys, time, urllib.request, tempfile
import websockets

URL = sys.argv[1]
STEPS = json.load(open(sys.argv[2]))
prof = tempfile.mkdtemp()
chrome = subprocess.Popen(["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "--headless=new",
    "--remote-debugging-port=9333", f"--user-data-dir={prof}", "--no-first-run", "about:blank"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            tabs = json.load(urllib.request.urlopen("http://127.0.0.1:9333/json")); break
        except Exception: time.sleep(0.2)
    ws_url = [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]

    async def main():
        async with websockets.connect(ws_url, max_size=2**26) as ws:
            n = 0
            async def call(method, **params):
                nonlocal n; n += 1; my = n
                await ws.send(json.dumps({"id": my, "method": method, "params": params}))
                while True:
                    m = json.loads(await ws.recv())
                    if m.get("method") == "Runtime.exceptionThrown":
                        print("JS EXCEPTION:", m["params"]["exceptionDetails"].get("exception", {}).get("description"))
                    if m.get("method") == "Runtime.consoleAPICalled":
                        print("console:", [a.get("value") for a in m["params"]["args"]])
                    if m.get("id") == my: return m
            await call("Runtime.enable"); await call("Page.enable")
            await call("Page.navigate", url=URL); await asyncio.sleep(2)
            for step in STEPS:
                if isinstance(step, (int, float)): await asyncio.sleep(step); continue
                r = await call("Runtime.evaluate", expression=step, awaitPromise=True, returnByValue=True)
                res = r.get("result", {})
                print(">", step[:90].replace("\n", " "), "=>", res.get("result", {}).get("value", res.get("exceptionDetails", {}).get("text")))
    asyncio.run(main())
finally:
    chrome.terminate()
