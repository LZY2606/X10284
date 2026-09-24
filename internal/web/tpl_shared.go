package web

const sharedTemplate = `
{{define "header"}}<!doctype html><html><head><meta charset="utf-8">
<title>MQTT 会话印迹复核</title><style>
body{font:14px/1.5 -apple-system,Segoe UI,sans-serif;margin:0;background:#f7fafc;color:#1a202c}
nav{background:#1a365d;color:#fff;padding:8px 16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
nav a{color:#bee3f8;text-decoration:none}
main{padding:16px;max-width:1100px;margin:auto}
h2{margin-top:24px;border-bottom:2px solid #cbd5e0;padding-bottom:4px}
h4{margin:8px 0}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;margin:10px 0}
table{border-collapse:collapse;width:100%;background:#fff}
td,th{border:1px solid #e2e8f0;padding:4px 8px;text-align:left;font-size:13px;vertical-align:top}
th{background:#edf2f7}
.tag{display:inline-block;background:#ebf8ff;border:1px solid #90cdf4;border-radius:10px;padding:0 8px;font-size:11px;margin-left:4px}
.tag.warn{background:#fffaf0;border-color:#f6ad55}
.tag.bad{background:#fff5f5;border-color:#fc8181}
.tag.ok{background:#f0fff4;border-color:#68d391}
.tag.purple{background:#faf5ff;border-color:#b794f4}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.muted{color:#718096;font-size:12px}
.id{color:#805ad5;font-family:ui-monospace,monospace;font-size:11px}
svg.svg{background:#fff;border:1px solid #e2e8f0;border-radius:8px;margin:6px 0;max-width:100%}
.svghit:hover{filter:brightness(.95)}
a{color:#2b6cb0}
button{padding:6px 12px;border-radius:6px;border:1px solid #2b6cb0;background:#2b6cb0;color:#fff;cursor:pointer}
button.ghost{background:#fff;color:#2b6cb0}
code{background:#edf2f7;padding:1px 4px;border-radius:3px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
</style></head><body>
<nav><b>MQTT 会话印迹</b>
<a href="/">代次总览</a><a href="/events">事件</a><a href="/branches">分支/冲突</a>
<a href="/tour">90 秒路径</a><a href="/export">导出</a>
<form method="post" action="/import" enctype="multipart/form-data" style="display:flex;gap:6px;align-items:center">
<input type="file" name="file" accept=".ndjson" style="font-size:11px"><button type="submit">导入</button></form>
<span class="muted" style="color:#a0aec0">当前版本 <span class="id">{{.HeadID}}</span></span>
</nav><main>{{end}}
{{define "footer"}}</main></body></html>{{end}}
{{define "versionSwitch"}}
<div class="muted">查看版本:
<select onchange="if(this.value)location.href=this.value" style="font-family:ui-monospace,monospace;font-size:11px">
{{range .Versions}}<option value="/version/{{.ID}}" {{if eq .ID $.Version.ID}}selected{{end}}>{{.ID}} — {{.Label}}</option>{{end}}
</select>
</div>{{end}}
`
