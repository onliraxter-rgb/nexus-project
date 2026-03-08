import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

def apply_replacements():
    index_path = r"c:\Users\onlir\Downloads\nexus-complete-project\nexus-project\frontend\index.html"
    prompt_path = r"c:\Users\onlir\Downloads\NEXUS_AGENT_PROMPT.md"

    with open(prompt_path, 'r', encoding='utf-8') as f:
        prompt = f.read()

    with open(index_path, 'r', encoding='utf-8') as f:
        html = f.read()

    success_count = 0
    fail_count = 0

    def replace_regex(pattern, replace_str):
        nonlocal html, success_count, fail_count
        new_html, count = re.subn(pattern, replace_str, html, count=1)
        if count > 0:
            html = new_html
            success_count += 1
            print(f"[OK] Regex replaced: {pattern[:30]}...")
        else:
            fail_count += 1
            print(f"[FAIL] Regex could not find: {pattern[:30]}...")


    replace_regex(r'\.topbar\{display:flex;align-items:center;gap:6px;padding:7px 14px;border-bottom:1px solid rgba\(255,255,255,\.05\);background:#050505;flex-shrink:0\}', '.topbar{display:flex;align-items:center;gap:6px;padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#050505;flex-shrink:0}')
    replace_regex(r'\.toolbar\{display:flex;align-items:center;gap:3px;padding:5px 14px;border-bottom:1px solid rgba\(255,255,255,\.05\);background:#030303;flex-shrink:0;flex-wrap:wrap\}', '.toolbar{display:flex;align-items:center;gap:3px;padding:5px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#030303;flex-shrink:0;flex-wrap:wrap}')
    replace_regex(r'\.kpi-value\{font-family:var\(--fm\);[^\}]+\}', '.kpi-value{font-family:var(--fm);font-size:22px;font-weight:900;color:#f0f4f8;letter-spacing:-.03em;line-height:1}')
    replace_regex(r'\.layer-hdr span:last-child\{[^\}]+\}', '.layer-hdr span:last-child{font-size:13px;font-weight:800;color:#e2e8f0}')
    replace_regex(r'\.verdict-box\{[^\}]+\}', '.verdict-box{margin:14px 0 7px;padding:14px 18px;background:linear-gradient(135deg,rgba(167,139,250,.12),rgba(52,211,153,.06));border:1px solid rgba(167,139,250,.3);border-radius:10px;font-family:var(--fm);font-size:13px;font-weight:700;color:#c4b5fd;letter-spacing:.02em;border-left:3px solid #a78bfa}')
    replace_regex(r'\.sug-chip\{font-family:var\(--fm\);font-size:8\.5px;padding:3px 11px;', '.sug-chip{font-family:var(--fm);font-size:11px;padding:6px 14px;')
    replace_regex(r'\.chart-card\s*canvas\{[^\}]+\}', '.chart-card canvas{max-height:240px}\n.chart-card{margin:12px 0;background:#0a0a0a;border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 10px}')
    replace_regex(r'\.mrow\{padding:10px 16px;display:flex;gap:11px;', '.mrow{padding:10px 16px;display:flex;gap:11px;')
    replace_regex(r'\.inp-zone\{[^\}]+\}', '.inp-zone{padding:8px 14px 9px;border-top:1px solid rgba(255,255,255,.06);background:#050505;flex-shrink:0;z-index:10}')


    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(html)
        
    print(f"Applied fixes script 2. Success: {success_count}, Fails: {fail_count}")

if __name__ == "__main__":
    apply_replacements()
