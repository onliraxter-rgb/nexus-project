import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

def apply_replacements():
    index_path = r"c:\Users\onlir\Downloads\nexus-complete-project\nexus-project\frontend\index.html"
    prompt_path = r"c:\Users\onlir\Downloads\ANTIGRAVITY_V9_COMPLETE.md"

    with open(prompt_path, 'r', encoding='utf-8') as f:
        prompt = f.read()

    with open(index_path, 'r', encoding='utf-8') as f:
        html = f.read()

    # B1: :root
    b1_repl = re.search(r'(:root\{[\s\S]*?\})', prompt.split("### B1")[1])
    if b1_repl: html = re.sub(r':root\s*\{[^}]+\}', b1_repl.group(1), html, count=1)

    # B2: PURE BLACK DASHBOARD BACKGROUND
    b2_repl = re.search(r'```css\n(.*?)```', re.split(r'\*\*REPLACE WITH:\*\*', prompt.split("### B2")[1], flags=re.I)[1], re.DOTALL)
    if b2_repl: html = re.sub(r'\[data-theme="dark"\] #view-dash::before\{[^}]+\}', b2_repl.group(1).strip(), html, count=1)

    # B3: CHAT BUBBLE CSS
    if "### B3" in prompt:
        m = re.search(r'```css\n(.*?\.bub\{[\s\S]*?\.bub\.u\{[^}]+\})\s*```', prompt.split("### B3")[1], re.DOTALL)
        if m: html = re.sub(r'\.bub\{[^}]+\}\s*\.bub\.ai\{[^}]+\}\s*\.bub\.u\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B4: Paragraph and List CSS
    if "### B4" in prompt:
        m = re.search(r'```css\n(\.mp\{[\s\S]*?td[^\{]*\{[^}]+\})\s*```', prompt.split("### B4")[1], re.DOTALL)
        if m: html = re.sub(r'\.mp\{[\s\S]*?td\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B5: Table Header CSS
    if "### B5" in prompt:
        m = re.search(r'```css\n(\.hdr-row\s*th\{[^}]+\})\s*```', prompt.split("### B5")[1], re.DOTALL)
        if m: html = re.sub(r'\.hdr-row\s*th\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B6: Section Divider
    if "### B6" in prompt:
        m = re.search(r'```css\n(\.sec-div\{[\s\S]*?\.tbl-wrap\{[^}]+\})\s*```', prompt.split("### B6")[1], re.DOTALL)
        if m: html = re.sub(r'\.sec-div\{[\s\S]*?\.tbl-wrap\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B7: KPI Card CSS
    if "### B7" in prompt:
        m = re.search(r'```css\n(\.kpi-grid\{[\s\S]*?\.kpi-delta\.neutral\{[^}]+\})\s*```', prompt.split("### B7")[1], re.DOTALL)
        if m: html = re.sub(r'\.kpi-grid\{[\s\S]*?\.kpi-delta\.neutral\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B8: Chart Card CSS
    if "### B8" in prompt:
        m = re.search(r'```css\n(\.chart-card\{[\s\S]*?\.chart-card\s*canvas\{[^}]+\})\s*```', prompt.split("### B8")[1], re.DOTALL)
        if m: html = re.sub(r'\.chart-card\{[\s\S]*?\.chart-card\s*canvas\{[^}]+\}', m.group(1).strip(), html, count=1)

    # B9: ADD NEW CSS
    if "### B9" in prompt:
        m = re.search(r'ADD this new CSS block:\s*```css\n(.*?)```', prompt.split("### B9")[1], re.DOTALL)
        if m:
            new_css = m.group(1).strip()
            if ".chart-card canvas{" in html:
                html = re.sub(r'(\.chart-card\s*canvas\{[^}]+\})', r'\1\n' + new_css, html, count=1)

    # B10: Replace showFOk function
    if "### B10" in prompt:
        m = re.search(r'```(?:javascript)?\n(.*?)```', re.split(r'Replace the ENTIRE showFOk function with:\*\*', prompt.split("### B10")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_js = m.group(1).strip()
            html = re.sub(r'function showFOk\(fname,info\)\{.*?(?=\s*function |\s*</script>)', new_js + "\n", html, count=1, flags=re.DOTALL)

    # B11: renderContent Auto Chart
    if "### B11" in prompt:
        m = re.search(r'```(?:javascript)?\n(.*?)```', re.split(r'Replace with:\*\*', prompt.split("### B11")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_js = m.group(1).strip()
            html = re.sub(r'const lines=text\.split\(\'\\n\'\);[\s\S]*?let html=kpis\.length\?`<div class="kpi-grid">\$\{kpis\.join\(\'\'\)\}<\/div>`:\'\';', new_js, html, count=1)

    # B12: chart-type switcher tabs
    if "### B12" in prompt:
        m = re.search(r'```(?:javascript)?\n(.*?)```', re.split(r'Replace with:\*\*', prompt.split("### B12")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_js = m.group(1).strip()
            html = re.sub(r'return`<div class="chart-card" id="\$\{id\}">.*?<\/div>`;', new_js, html, count=1, flags=re.DOTALL)

    # B13: switchCType function
    if "### B13" in prompt:
        m = re.search(r'```(?:javascript)?\n(.*?)```', prompt.split("### B13")[1], re.DOTALL)
        if m:
            new_js = m.group(1).strip()
            if "function switchCType" not in html:
                html = html.replace("</script>", new_js + "\n</script>", 1)

    # B14: SYSTEM PROMPT Update
    if "### B14" in prompt:
        m = re.search(r'```(?:javascript)?\n(.*?)```', re.split(r'Replace with:\*\*', prompt.split("### B14")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_js = m.group(1).strip()
            html = re.sub(r'9\. VISUALIZATIONS:[^\n]*', new_js, html, count=1)

    # B15: Version badge
    if "### B15" in prompt:
        m = re.search(r'```html\n(.*?)```', re.split(r'Replace with:\*\*', prompt.split("### B15")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_html = m.group(1).strip()
            html = re.sub(r'<div class="ver" id="dashVer">.*?<\/div>', new_html, html, count=1)

    # B16: Main background
    if "### B16" in prompt:
        html = re.sub(r'\.main\{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative;z-index:1(?!;background:#000000)\}', r'.main{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative;z-index:1;background:#000000}', html, count=1)
        html = re.sub(r'\.topbar\{display:flex;align-items:center;gap:6px;padding:6px 13px;border-bottom:1px solid var\(--br\);background:var\(--s1\);flex-shrink:0\}', r'.topbar{display:flex;align-items:center;gap:6px;padding:7px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#050505;flex-shrink:0}', html, count=1)
        html = re.sub(r'\.toolbar\{display:flex;align-items:center;gap:3px;padding:4px 13px;border-bottom:1px solid var\(--br\);background:var\(--s2\);flex-shrink:0;flex-wrap:wrap\}', r'.toolbar{display:flex;align-items:center;gap:3px;padding:5px 14px;border-bottom:1px solid rgba(255,255,255,.05);background:#030303;flex-shrink:0;flex-wrap:wrap}', html, count=1)

    # B17: Increase chat padding
    if "### B17" in prompt:
        html = re.sub(r'\.mrow\{padding:6px 13px;display:flex;gap:9px;animation:mi \.22s ease;position:relative\}', r'.mrow{padding:10px 16px;display:flex;gap:11px;animation:mi .22s ease;position:relative}', html, count=1)

    # B18: Replace Toolbar
    if "### B18" in prompt:
        m = re.search(r'```html\n(.*?)```', re.split(r'Replace ENTIRE toolbar div with:\*\*', prompt.split("### B18")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_html = m.group(1).strip()
            html = re.sub(r'<div class="toolbar">.*?</div>\n', new_html + "\n", html, count=1, flags=re.DOTALL)

        m2 = re.search(r'```javascript\n(.*?)```', re.split(r'Also add this JS function before the closing `</script>`:\*\*', prompt.split("### B18")[1], flags=re.I)[1], re.DOTALL)
        if m2:
            new_js = m2.group(1).strip()
            if "function setSugAndSend" not in html:
                html = html.replace("</script>", new_js + "\n</script>", 1)

    # B19: Suggestion chips
    if "### B19" in prompt:
        m = re.search(r'```html\n(.*?)```', re.split(r'REPLACE WITH:\*\*', prompt.split("### B19")[1], flags=re.I)[1], re.DOTALL)
        if m:
            new_html = m.group(1).strip()
            html = re.sub(r'<div class="inp-suggestions">.*?</div>', new_html, html, count=1, flags=re.DOTALL)

    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(html)
        
    print(f"Applied full robust regex replacements.")

if __name__ == "__main__":
    apply_replacements()
