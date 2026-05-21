#!/usr/bin/env python3
"""
Mobile Security Report Generator
Generates mobile-security-report.html from MobSF JSON output.
"""

import json
import os
import sys
from datetime import datetime, timezone

# ── Environment ───────────────────────────────────────────────────────────────
REPO_NAME         = os.environ.get('REPO_NAME', 'unknown')
GITLAB_REPO_PATH  = os.environ.get('GITLAB_REPO_PATH', '')
REPO_COMMIT       = os.environ.get('REPO_COMMIT', 'unknown')
GIT_BRANCH        = os.environ.get('GIT_BRANCH', 'main')
BUILD_NUMBER      = os.environ.get('BUILD_NUMBER', '0')
BUILD_URL         = os.environ.get('BUILD_URL', '#')
PIPELINE_STATUS   = os.environ.get('PIPELINE_STATUS', 'UNKNOWN')
PIPELINE_FAIL_REASON = os.environ.get('PIPELINE_FAIL_REASON', '')
WORKSPACE         = os.environ.get('WORKSPACE', '.')
APK_NAME          = os.environ.get('APK_NAME', 'unknown.apk')
APK_SIZE          = os.environ.get('APK_SIZE', 'unknown')
MOBSF_HOST        = os.environ.get('MOBSF_HOST', 'http://mobsf.internal:8000')
MOBSF_HASH        = os.environ.get('MOBSF_HASH', '')
MOBSF_SCORE       = int(os.environ.get('MOBSF_SCORE', '0'))
MOBSF_HIGH        = int(os.environ.get('MOBSF_HIGH', '0'))
MOBSF_WARNING     = int(os.environ.get('MOBSF_WARNING', '0'))
MOBSF_INFO        = int(os.environ.get('MOBSF_INFO', '0'))
MOBSF_MANIFEST    = int(os.environ.get('MOBSF_MANIFEST_ISSUES', '0'))
MOBSF_PERMS       = int(os.environ.get('MOBSF_DANGEROUS_PERMS', '0'))
MOBSF_SECRETS     = int(os.environ.get('MOBSF_SECRETS', '0'))
MOBSF_TRACKERS    = int(os.environ.get('MOBSF_TRACKERS', '0'))
SCAN_DATE         = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

# ── Load MobSF report ─────────────────────────────────────────────────────────
report = {}
report_path = os.path.join(WORKSPACE, 'mobsf-report.json')
try:
    with open(report_path, 'r', encoding='utf-8') as f:
        report = json.load(f)
except Exception as e:
    print(f"Warning: could not load mobsf-report.json: {e}")

# ── Helpers ───────────────────────────────────────────────────────────────────
def score_color(score):
    if score >= 70: return '#1E5631'
    if score >= 50: return '#7B4F00'
    return '#7B1F1F'

def score_bg(score):
    if score >= 70: return '#D4EDDA'
    if score >= 50: return '#FFF3CD'
    return '#FDECEA'

def sev_badge(sev):
    sev = (sev or '').lower()
    colors = {
        'high':    ('FDECEA', '7B1F1F'),
        'warning': ('FFF3CD', '7B4F00'),
        'info':    ('EBF3FA', '1A3A5C'),
        'secure':  ('D4EDDA', '1E5631'),
    }
    bg, fg = colors.get(sev, ('F0F0F0', '404040'))
    label = sev.upper()
    return f'<span style="background:#{bg};color:#{fg};padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">{label}</span>'

def esc(s):
    if not s: return ''
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

# ── Extract data from report ───────────────────────────────────────────────────
app_name     = esc(report.get('app_name', APK_NAME))
app_version  = esc(report.get('app_version', 'N/A'))
package_name = esc(report.get('package_name', 'N/A'))
min_sdk      = esc(report.get('min_sdk', 'N/A'))
target_sdk   = esc(report.get('target_sdk', 'N/A'))
avg_cvss     = report.get('average_cvss', 0)
md5          = esc(report.get('md5', ''))
sha256_hash  = esc(report.get('sha256', ''))

# Findings
findings = report.get('appsec', {}).get('findings', [])
high_findings    = [f for f in findings if (f.get('severity') or '').lower() == 'high']
warning_findings = [f for f in findings if (f.get('severity') or '').lower() == 'warning']
info_findings    = [f for f in findings if (f.get('severity') or '').lower() == 'info']
secure_findings  = [f for f in findings if (f.get('severity') or '').lower() == 'secure']

# Permissions
permissions = report.get('permissions', {})
dangerous_perms = {k: v for k, v in permissions.items()
                   if (v.get('status') or '').lower() == 'dangerous'}
normal_perms    = {k: v for k, v in permissions.items()
                   if (v.get('status') or '').lower() != 'dangerous'}

# Manifest issues
manifest_issues = report.get('manifest_analysis', [])

# Secrets
secrets_list = report.get('secrets', [])

# Trackers
trackers_data    = report.get('trackers', {})
detected_trackers = trackers_data.get('detected_trackers', 0)
tracker_list     = trackers_data.get('trackers', [])

# Certificate
certificate = report.get('certificate_analysis', {})

# ── Build findings rows ───────────────────────────────────────────────────────
def findings_rows(flist):
    if not flist:
        return '<tr><td colspan="3" style="text-align:center;color:#888;font-style:italic;padding:16px;">No findings</td></tr>'
    rows = ''
    for f in flist:
        title    = esc(f.get('title') or f.get('issue') or 'Security issue')
        desc     = esc(f.get('description') or f.get('metadata') or '')
        sev      = f.get('severity', '')
        rows += f'''<tr>
            <td style="width:90px;">{sev_badge(sev)}</td>
            <td style="font-weight:600;color:#1A3A5C;">{title}</td>
            <td style="color:#595959;font-size:12px;">{desc[:200]}</td>
        </tr>'''
    return rows

# ── MobSF report URL ──────────────────────────────────────────────────────────
mobsf_url = f"{MOBSF_HOST}/static_analysis/?name={APK_NAME}&checksum={MOBSF_HASH}&type=apk"

# ── Status bar ────────────────────────────────────────────────────────────────
if PIPELINE_STATUS == 'PASSED':
    status_bg     = '#D4EDDA'
    status_border = '#1E5631'
    status_text   = '#1E5631'
    status_icon   = '✅'
else:
    status_bg     = '#FDECEA'
    status_border = '#7B1F1F'
    status_text   = '#7B1F1F'
    status_icon   = '❌'

# ── HTML ──────────────────────────────────────────────────────────────────────
html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mobile Security Report — {app_name}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: Arial, sans-serif; font-size: 14px; color: #404040;
        background: #F8F9FA; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
.header {{ background: #1A3A5C; color: white; padding: 28px 32px;
           border-radius: 8px; margin-bottom: 20px; }}
.header h1 {{ font-size: 22px; font-weight: 700; }}
.header .sub {{ font-size: 13px; opacity: 0.85; margin-top: 4px; }}
.meta {{ display: grid; grid-template-columns: repeat(3,1fr); gap: 8px; margin-top: 16px; }}
.meta-item {{ background: rgba(255,255,255,0.1); padding: 8px 12px; border-radius: 4px; }}
.meta-item .label {{ font-size: 11px; text-transform: uppercase; opacity: 0.7; }}
.meta-item .value {{ font-weight: 600; font-size: 13px; word-break: break-all; }}
.status-bar {{ padding: 14px 20px; border-radius: 8px; margin-bottom: 20px;
               display: flex; align-items: center; gap: 16px;
               background: {status_bg}; border-left: 6px solid {status_border}; }}
.s-label {{ font-size: 20px; font-weight: 700; color: {status_text}; }}
.s-reason {{ font-size: 13px; color: #595959; }}
.score-box {{ background: white; border-radius: 8px; padding: 24px;
              border: 1px solid #E0E0E0; margin-bottom: 20px;
              display: flex; align-items: center; gap: 32px; }}
.score-circle {{ width: 100px; height: 100px; border-radius: 50%;
                 background: {score_bg(MOBSF_SCORE)};
                 display: flex; flex-direction: column;
                 align-items: center; justify-content: center; flex-shrink: 0; }}
.score-num {{ font-size: 32px; font-weight: 700; color: {score_color(MOBSF_SCORE)}; }}
.score-label {{ font-size: 11px; color: {score_color(MOBSF_SCORE)}; text-transform: uppercase; }}
.grid4 {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 20px; }}
.card {{ background: white; border-radius: 8px; padding: 20px;
         text-align: center; border: 1px solid #E0E0E0; }}
.card .count {{ font-size: 36px; font-weight: 700; }}
.card .clabel {{ font-size: 12px; color: #595959; text-transform: uppercase; margin-top: 4px; }}
.card.high .count {{ color: #7B1F1F; }}
.card.warn .count {{ color: #7B4F00; }}
.card.perm .count {{ color: #1A3A5C; }}
.card.track .count {{ color: #7B4F00; }}
.section {{ background: white; border-radius: 8px; padding: 24px;
            margin-bottom: 20px; border: 1px solid #E0E0E0; }}
.section h2 {{ font-size: 18px; font-weight: 600; color: #1A3A5C;
               padding-bottom: 10px; border-bottom: 2px solid #D6E4F0;
               margin-bottom: 14px; }}
.section h3 {{ font-size: 14px; font-weight: 600; color: #595959;
               margin: 16px 0 8px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: #EBF3FA; color: #1A3A5C; font-weight: 600;
      padding: 10px 12px; text-align: left; border-bottom: 2px solid #D6E4F0; }}
td {{ padding: 9px 12px; border-bottom: 1px solid #F0F0F0; vertical-align: top; }}
tr:last-child td {{ border-bottom: none; }}
tr:hover td {{ background: #FAFAFA; }}
.mono {{ font-family: monospace; font-size: 12px; }}
.tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 11px; font-weight: 600; margin: 2px;
        background: #EBF3FA; color: #1A3A5C; }}
.tag.danger {{ background: #FDECEA; color: #7B1F1F; }}
a {{ color: #2E75B6; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.footer {{ text-align: center; font-size: 12px; color: #888;
           margin-top: 20px; padding: 16px; }}
.empty {{ text-align:center; color:#888; font-style:italic; padding:16px; }}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <h1>Mobile Security Report — {app_name}</h1>
    <div class="sub">MobSF Static Analysis · {APK_NAME}</div>
    <div class="meta">
      <div class="meta-item">
        <div class="label">Repository</div>
        <div class="value">{esc(GITLAB_REPO_PATH)}</div>
      </div>
      <div class="meta-item">
        <div class="label">Package</div>
        <div class="value">{package_name}</div>
      </div>
      <div class="meta-item">
        <div class="label">Version</div>
        <div class="value">{app_version}</div>
      </div>
      <div class="meta-item">
        <div class="label">Min SDK / Target SDK</div>
        <div class="value">{min_sdk} / {target_sdk}</div>
      </div>
      <div class="meta-item">
        <div class="label">Build</div>
        <div class="value">#{BUILD_NUMBER}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scan date</div>
        <div class="value">{SCAN_DATE}</div>
      </div>
    </div>
  </div>

  <!-- Status bar -->
  <div class="status-bar">
    <div class="s-label">{PIPELINE_STATUS} {status_icon}</div>
    <div class="s-reason">{esc(PIPELINE_FAIL_REASON) if PIPELINE_FAIL_REASON else 'All security checks passed.'}</div>
  </div>

  <!-- Security score -->
  <div class="score-box">
    <div class="score-circle">
      <div class="score-num">{MOBSF_SCORE}</div>
      <div class="score-label">/ 100</div>
    </div>
    <div>
      <div style="font-size:20px;font-weight:700;color:#1A3A5C;margin-bottom:6px;">
        Security Score
      </div>
      <div style="color:#595959;font-size:13px;">
        MobSF scores APKs from 0 (insecure) to 100 (secure).
        Minimum passing threshold: <strong>50</strong>.
        Average CVSS: <strong>{avg_cvss}</strong>.
      </div>
      <div style="margin-top:10px;">
        <a href="{mobsf_url}" target="_blank" style="font-size:13px;">
          View full MobSF report →
        </a>
      </div>
    </div>
  </div>

  <!-- Summary cards -->
  <div class="grid4">
    <div class="card high">
      <div class="count">{MOBSF_HIGH}</div>
      <div class="clabel">High findings</div>
    </div>
    <div class="card warn">
      <div class="count">{MOBSF_WARNING}</div>
      <div class="clabel">Warnings</div>
    </div>
    <div class="card perm">
      <div class="count">{MOBSF_PERMS}</div>
      <div class="clabel">Dangerous perms</div>
    </div>
    <div class="card track">
      <div class="count">{detected_trackers}</div>
      <div class="clabel">Trackers</div>
    </div>
  </div>

  <!-- App info -->
  <div class="section">
    <h2>Application information</h2>
    <table>
      <tr><th style="width:200px;">Property</th><th>Value</th></tr>
      <tr><td>App name</td><td>{app_name}</td></tr>
      <tr><td>Package name</td><td class="mono">{package_name}</td></tr>
      <tr><td>Version</td><td>{app_version}</td></tr>
      <tr><td>APK file</td><td class="mono">{esc(APK_NAME)}</td></tr>
      <tr><td>APK size</td><td>{esc(APK_SIZE)}</td></tr>
      <tr><td>Min SDK</td><td>{min_sdk}</td></tr>
      <tr><td>Target SDK</td><td>{target_sdk}</td></tr>
      <tr><td>MD5</td><td class="mono">{md5}</td></tr>
      <tr><td>SHA256</td><td class="mono" style="font-size:11px;">{sha256_hash}</td></tr>
    </table>
  </div>

  <!-- HIGH findings -->
  <div class="section">
    <h2>HIGH severity findings ({len(high_findings)})</h2>
    <table>
      <tr>
        <th style="width:90px;">Severity</th>
        <th style="width:280px;">Issue</th>
        <th>Description</th>
      </tr>
      {findings_rows(high_findings)}
    </table>
  </div>

  <!-- Warnings -->
  <div class="section">
    <h2>Warnings ({len(warning_findings)})</h2>
    <table>
      <tr>
        <th style="width:90px;">Severity</th>
        <th style="width:280px;">Issue</th>
        <th>Description</th>
      </tr>
      {findings_rows(warning_findings)}
    </table>
  </div>

  <!-- Permissions -->
  <div class="section">
    <h2>Permissions</h2>
    <h3>Dangerous permissions ({len(dangerous_perms)})</h3>
    <table>
      <tr>
        <th style="width:300px;">Permission</th>
        <th>Description</th>
      </tr>
'''

if dangerous_perms:
    for perm, details in dangerous_perms.items():
        desc = esc(details.get('description') or '')
        html += f'''      <tr>
        <td class="mono"><span class="tag danger">{esc(perm)}</span></td>
        <td style="font-size:12px;color:#595959;">{desc}</td>
      </tr>
'''
else:
    html += '      <tr><td colspan="2" class="empty">No dangerous permissions detected</td></tr>\n'

html += f'''    </table>
  </div>

  <!-- Manifest issues -->
  <div class="section">
    <h2>Manifest analysis ({len(manifest_issues)} issues)</h2>
    <table>
      <tr>
        <th style="width:90px;">Severity</th>
        <th style="width:280px;">Rule</th>
        <th>Description</th>
      </tr>
'''

manifest_list = list(manifest_issues) if isinstance(manifest_issues, list) else list(manifest_issues.values()) if isinstance(manifest_issues, dict) else []
if manifest_list:
    for item in manifest_list[:20]:
        if not isinstance(item, dict):
            continue
        sev  = item.get('severity', 'info')
        rule = esc(item.get('rule') or item.get('title') or 'Manifest issue')
        desc = esc(item.get('description') or '')
        html += f'''      <tr>
        <td>{sev_badge(sev)}</td>
        <td style="font-weight:600;color:#1A3A5C;font-size:12px;">{rule}</td>
        <td style="color:#595959;font-size:12px;">{desc[:200]}</td>
      </tr>
'''
else:
    html += '      <tr><td colspan="3" class="empty">No manifest issues detected</td></tr>\n'

html += f'''    </table>
  </div>

  <!-- Secrets -->
  <div class="section">
    <h2>Hardcoded secrets ({len(secrets_list)})</h2>
    <table>
      <tr>
        <th style="width:200px;">Type</th>
        <th>Value / Location</th>
      </tr>
'''

secrets_safe = secrets_list if isinstance(secrets_list, list) else []
if secrets_safe:
    for s in secrets_safe[:20]:
        if not isinstance(s, dict):
            continue
        stype = esc(s.get('type') or s.get('name') or 'Secret')
        val   = esc(str(s.get('match') or s.get('value') or '')[:100])
        html += f'''      <tr>
        <td style="font-weight:600;color:#7B1F1F;">{stype}</td>
        <td class="mono" style="font-size:11px;">{val}</td>
      </tr>
'''
else:
    html += '      <tr><td colspan="2" class="empty">No hardcoded secrets detected</td></tr>\n'

html += f'''    </table>
  </div>

  <!-- Trackers -->
  <div class="section">
    <h2>Trackers detected ({detected_trackers})</h2>
    <table>
      <tr>
        <th style="width:250px;">Tracker</th>
        <th>Categories</th>
      </tr>
'''

if tracker_list:
    for t in tracker_list:
        name = esc(t.get('name') or 'Unknown tracker')
        cats = esc(', '.join(t.get('categories') or []))
        html += f'''      <tr>
        <td style="font-weight:600;">{name}</td>
        <td style="font-size:12px;color:#595959;">{cats}</td>
      </tr>
'''
else:
    html += '      <tr><td colspan="2" class="empty">No trackers detected</td></tr>\n'

html += f'''    </table>
  </div>

  <!-- Scan metadata -->
  <div class="section">
    <h2>Scan metadata</h2>
    <table>
      <tr><th style="width:200px;">Item</th><th>Value</th></tr>
      <tr><td>Repository</td><td>{esc(REPO_NAME)}</td></tr>
      <tr><td>Commit SHA</td><td class="mono">{esc(REPO_COMMIT)}</td></tr>
      <tr><td>Branch</td><td>{esc(GIT_BRANCH)}</td></tr>
      <tr><td>Build</td><td>#{BUILD_NUMBER}</td></tr>
      <tr><td>Scan date</td><td>{SCAN_DATE}</td></tr>
      <tr><td>Pipeline status</td><td><strong>{PIPELINE_STATUS}</strong></td></tr>
      <tr><td>MobSF version</td><td>4.5.0</td></tr>
      <tr><td>MobSF report</td>
          <td><a href="{mobsf_url}" target="_blank">View in MobSF →</a></td></tr>
    </table>
  </div>

  <div class="footer">
    Generated by the Mobile Security Pipeline · MobSF v4.5.0 ·
    Jenkins Build #{BUILD_NUMBER} · {SCAN_DATE}
  </div>

</div>
</body>
</html>'''

# ── Write output ──────────────────────────────────────────────────────────────
output_path = os.path.join(WORKSPACE, 'mobile-security-report.html')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(html)

print(f"Mobile security report generated: {output_path}")
print(f"  App name     : {app_name}")
print(f"  Score        : {MOBSF_SCORE}/100")
print(f"  High findings: {MOBSF_HIGH}")
print(f"  Warnings     : {MOBSF_WARNING}")
print(f"  Secrets      : {MOBSF_SECRETS}")
print(f"  Trackers     : {detected_trackers}")
