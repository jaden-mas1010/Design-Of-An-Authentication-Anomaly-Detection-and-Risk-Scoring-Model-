for fn in ["engine/ml_scorer.py", "engine/correlator.py"]:
    with open(fn, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    idx = text.find('"""')
    if idx == -1:
        print(fn, "no docstring marker found - not touched")
        continue
    text = text[idx:]
    with open(fn, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(fn, "fixed, now starts with:", repr(text[:20]))
