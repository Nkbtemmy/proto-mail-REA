import sys, json, urllib.request, time, pathlib
prompt_file, out_file = sys.argv[1], sys.argv[2]
prompt = pathlib.Path(prompt_file).read_text()
body = json.dumps({
    "model": "manzi-14b:latest",
    "prompt": prompt,
    "stream": False,
    "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 2048}
}).encode()
t0 = time.time()
req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                             headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=1800) as r:
    d = json.load(r)
pathlib.Path(out_file).write_text(d.get("response", ""))
meta = {"eval_count": d.get("eval_count"), "wall_seconds": round(time.time()-t0,1),
        "tok_per_s": round((d.get("eval_count") or 0)/max(time.time()-t0,0.1),2)}
print(json.dumps(meta))
