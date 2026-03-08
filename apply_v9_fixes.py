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

    def replace_exact(find_str, replace_str):
        nonlocal html, success_count, fail_count
        if find_str in html:
            html = html.replace(find_str, replace_str, 1)
            success_count += 1
            print(f"[OK] Replaced: {find_str[:30]}...")
        else:
            fail_count += 1
            print(f"[FAIL] Could not find: {find_str[:30]}...")

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

    # FIX 1: Touch/click broken
    replace_exact('<body', '<body style="touch-action:manipulation"')
    replace_exact("loadSession();", "document.addEventListener('touchstart',function(){},{passive:true});\ndocument.addEventListener('touchend',function(){},{passive:true});\nloadSession();")

    # FIX 2: Pure black dashboard (CSS variables)
    replace_exact("--bg:#07080c;--s1:#0b0d14;--s2:#0f1119;--s3:#13151f;--s4:#181d28;", "--bg:#000000;--s1:#080808;--s2:#0d0d0d;--s3:#111111;--s4:#161616;")
    
    # Let's use regex for the complex ones just in case white spacing changed
    replace_regex(r'\[data-theme="dark"\] #view-dash::before\{[^\}]+\}', '[data-theme="dark"] #view-dash::before{display:none}')
    replace_regex(r'\.glow-bg\{[^\}]+\}', '.glow-bg{display:none}')

    # FIX 3: Dashboard area pure black
    if ".main{flex:1" in html and "background:#000000" not in html:
        html = re.sub(r'\.main\{flex:1(.*?)\}', r'.main{flex:1\1;background:#000000}', html, count=1)
        success_count += 1
        print("[OK] .main background added")

    replace_regex(r'\.topbar\{display:flex;align-items:center;gap:6px;padding:6px 13px;border-bottom:1px solid var\(--br\);background:var\(--s1\);flex-shrink:0\}', '.topbar{display:flex;align-items:center;gap:6px;padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#050505;flex-shrink:0}')
    replace_regex(r'\.toolbar\{display:flex;align-items:center;gap:3px;padding:4px 13px;border-bottom:1px solid var\(--br\);background:var\(--s2\);flex-shrink:0;flex-wrap:wrap\}', '.toolbar{display:flex;align-items:center;gap:3px;padding:5px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#030303;flex-shrink:0;flex-wrap:wrap}')
    replace_regex(r'\.inp-zone\{padding:6px 13px 7px;border-top:1px solid var\(--br\);background:var\(--s1\);flex-shrink:0;z-index:10\}', '.inp-zone{padding:8px 14px 9px;border-top:1px solid rgba(255,255,255,.06);background:#050505;flex-shrink:0;z-index:10}')
    replace_regex(r'\.bub\.ai\{background:var\(--s1\);border:1px solid var\(--br\);border-left:2px solid rgba\(124,58,237,\.4\)\}', '.bub.ai{background:#0d0d0d;border:1px solid rgba(255,255,255,.07);border-left:3px solid #7c3aed}')

    # FIX 4: Bigger readable text
    replace_regex(r'\.bub\{max-width:860px;flex:1;padding:9px 13px;border-radius:9px;font-size:12px;line-height:1\.75\}', '.bub{max-width:900px;flex:1;padding:14px 18px;border-radius:10px;font-size:14px;line-height:1.9}')
    replace_regex(r'\.mp\{margin:3px 0;font-size:12px;color:var\(--tx\)\}', '.mp{margin:5px 0;font-size:14px;color:#c8d4de;line-height:1.9}')
    replace_regex(r'\.ml li\{margin:2px 0;color:var\(--mt\);font-size:11px\}', '.ml li{margin:4px 0;color:#b0bec8;font-size:13px;line-height:1.7}')
    replace_regex(r'td\{padding:4px 9px;border-bottom:1px solid rgba\(255,255,255,\.04\);color:var\(--mt\);font-size:11px\}', 'td{padding:7px 11px;border-bottom:1px solid rgba(255,255,255,.05);color:#9ba8b5;font-size:13px}')
    replace_regex(r'\.kpi-value\{font-size:16px;font-weight:900;color:var\(--hd\)\}', '.kpi-value{font-size:22px;font-weight:900;color:#f0f4f8;letter-spacing:-.03em;line-height:1}')
    replace_regex(r'\.layer-hdr span:last-child\{font-size:10px;font-weight:800;color:var\(--hd\)\}', '.layer-hdr span:last-child{font-size:13px;font-weight:800;color:#e2e8f0}')
    replace_regex(r'\.verdict-box\{margin:11px 0 5px;padding:7px 13px;background:linear-gradient\(90deg,rgba\(167,139,250,\.1\),rgba\(52,211,153,\.06\)\);border:1px solid rgba\(167,139,250,\.3\);border-radius:7px;font-family:var\(--fm\);font-size:10px;font-weight:600;color:var\(--v\);letter-spacing:\.06em\}', '.verdict-box{margin:14px 0 7px;padding:14px 18px;background:linear-gradient(135deg,rgba(167,139,250,.12),rgba(52,211,153,.06));border:1px solid rgba(167,139,250,.3);border-radius:10px;font-family:var(--fm);font-size:13px;font-weight:700;color:#c4b5fd;letter-spacing:.02em;border-left:3px solid #a78bfa}')

    # FIX 5: Julius-style Dataset Card on file upload
    b5_css = re.search(r'```css\n(.*?\.dc-q-fill\{[^\}]+\})\s*```', prompt.split("### FIX 5: Julius-style Dataset Card on file upload")[1], re.DOTALL)
    if b5_css:
        new_css = b5_css.group(1).strip()
        html = re.sub(r'(\.chart-card\s*canvas\{max-height:190px\})', r'\1\n' + new_css, html, count=1)
        success_count += 1
        print("[OK] Added Fix 5 CSS")
    
    b5_js = re.search(r'```javascript\n(function showFOk\(fname,info\)\{.*?(?=\s*function |\s*</script>))\s*```', prompt.split("REPLACE the entire function with:")[1], re.DOTALL)
    if b5_js:
        new_js = b5_js.group(1).strip()
        html = re.sub(r'function showFOk\(fname,info\)\{.*?(?=\s*function |\s*</script>)', new_js + "\n", html, count=1, flags=re.DOTALL)
        success_count += 1
        print("[OK] Replaced showFOk JS")

    # FIX 6: Friendly error message (no raw JSON)
    b6_js = re.search(r'```javascript\n(const isRL=e\.message.*?\));\s*```', prompt.split("### FIX 6: Friendly error message")[1], re.DOTALL)
    if b6_js:
        new_js = b6_js.group(1).strip() + ";"
        html = re.sub(r'addBub\(\'ai\',\'(?:(?:\\\\u26a0\\\\ufe0f)?⚠️)? Error — credit refunded\\n\\n\'\+.*?\);', new_js, html, count=1)
        success_count += 1
        print("[OK] Replaced friendly error")

    # FIX 7: Enforce charts in system prompt
    b7_txt = re.search(r'ADD before it:\n```\n(MANDATORY:.*?)\n```', prompt, re.DOTALL)
    if b7_txt:
        html = html.replace('ALWAYS: Detect anomalies', b7_txt.group(1) + '\nALWAYS: Detect anomalies', 1)
        success_count += 1
        print("[OK] Enforced charts in system prompt")

    # FIX 8: Bigger suggestion chips
    replace_regex(r'\.sug-chip\{font-family:var\(--fm\);font-size:9px;', '.sug-chip{font-family:var(--fm);font-size:11px;padding:6px 14px;')

    # FIX 9: Hero section redesign (Julius/Dribbble style)
    b9_css = re.search(r'```css\n(/\* HERO REDESIGN.*?)\n```', prompt.split("### FIX 9:")[1], re.DOTALL)
    if b9_css:
        html = html.replace('</style>', b9_css.group(1).strip() + '\n</style>', 1)
        success_count += 1
        print("[OK] Hero CSS added")

    b9_html = re.search(r'```html\n(<div class="hero">.*?(?=</div>\s*</div>\s*</div>)</div>\s*</div>\s*</div>)\s*```', prompt.split("REPLACE the entire hero div content with:")[1], re.DOTALL)
    if b9_html:
        # Better safe replace: we know it starts with <div class="hero">
        m = re.search(r'<div class="hero">.*?(?=<div class="free-strip">)', html, re.DOTALL)
        if m:
            html = html.replace(m.group(0), b9_html.group(1).strip() + '\n', 1)
            success_count += 1
            print("[OK] Hero HTML replaced")

    # FIX 10: Chart type switcher tabs
    b10_js1 = re.search(r'```javascript\n(return`<div class="chart-card".*?</div>`;)\s*```', prompt.split("### FIX 10:")[1], re.DOTALL)
    if b10_js1:
        # replace return`<div class="chart-card"...
        html = re.sub(r'return`<div class="chart-card" id="\$\{id\}">.*?</div>`;', b10_js1.group(1).strip(), html, count=1, flags=re.DOTALL)
        success_count += 1
        print("[OK] Chart Switcher HTML replaced")

    b10_js2 = re.search(r'```javascript\n(function swChType.*?)\s*```', prompt.split("ADD this JS function before")[1], re.DOTALL)
    if b10_js2:
        if "function swChType" not in html:
            html = html.replace("loadSession();", b10_js2.group(1).strip() + "\nloadSession();", 1)
            success_count += 1
            print("[OK] swChType added")

    # FIX 11: Chart canvas bigger
    replace_regex(r'\.chart-card canvas\{max-height:190px\}', '.chart-card canvas{max-height:240px}\n.chart-card{margin:12px 0;background:#0a0a0a;border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:14px 14px 10px}')

    # FIX 12: Mrow bigger padding
    replace_regex(r'\.mrow\{padding:6px 13px;display:flex;gap:9px;', '.mrow{padding:10px 16px;display:flex;gap:11px;')

    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(html)
        
    print(f"Applied fixes script. Success: {success_count}, Fails: {fail_count}")

if __name__ == "__main__":
    apply_replacements()
