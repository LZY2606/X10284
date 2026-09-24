package web

const indexTemplate = `
{{define "index"}}{{template "header" .}}
<h2>会话代次（虚拟时钟）</h2>
{{template "versionSwitch" .}}
{{timeline .sessions ""}}
<table>
<tr><th>身份</th><th>client id</th><th>clean start</th><th>session expiry</th><th>会话存在</th><th>继承自</th><th>区间(ms)</th><th>来源包</th></tr>
{{range .sessions.Generations}}
<tr data-id="{{.ID}}">
 <td class="id">{{.ID}}</td><td>{{.ClientID}}</td>
 <td>{{if .CleanStart}}是{{else}}否{{end}}</td>
 <td class="mono">{{.SessionExpiryS}} s</td>
 <td>{{if .SessionPresent}}present{{else}}absent{{end}}</td>
 <td>{{if .CarriedFrom}}<a href="/gen?n={{.Index}}">{{.CarriedFrom}}</a>{{else}}—{{end}}</td>
 <td class="mono">{{.StartMS}}–{{.EndMS}}</td>
 <td><a href="/gen?n={{.Index}}">{{len .Packets}} packets</a></td>
</tr>{{end}}
</table>

<h2>QoS 状态机（按代次隔离的 packet id）</h2>
{{flowsSvg .flows.Flows .Version.ID}}

<h2>异常点</h2>
<table>
<tr><th>身份</th><th>类型</th><th>代次</th><th>说明</th><th>相关流</th><th>来源链</th></tr>
{{range .flows.Anomalies}}
<tr data-id="{{.ID}}">
 <td class="id">{{.ID}}</td>
 <td><span class="tag warn">{{.Code}}</span></td>
 <td class="mono">{{.Gen}}</td>
 <td>{{.Detail}}</td>
 <td>{{if .FlowID}}<a href="/flow?id={{.FlowID}}">{{.FlowID}}</a>{{else}}—{{end}}</td>
 <td><a href="/provenance/{{.ID}}">打开来源链 →</a></td>
</tr>{{else}}
<tr><td colspan="6" class="muted">无异常</td></tr>{{end}}
</table>

<h2>到期决定与裁定（多候选保留）</h2>
<table>
<tr><th>身份</th><th>类型</th><th>对象</th><th>候选</th><th>当前生效</th><th>依据基准</th><th>判断理由（机器可读）</th></tr>
{{$v := .}}
{{range decisionRows .}}
<tr data-id="{{.Dec.ID}}">
 <td class="id">{{.Dec.ID}}</td>
 <td>{{.Dec.Kind}}</td>
 <td>{{.Dec.Subject}}</td>
 <td>{{range .CandidateTag}}{{.}} {{end}}</td>
 <td>{{if .Overridden}}<span class="tag purple">{{.Effective}} (人工:{{.Reviewer}})</span>{{else}}<span class="tag ok">{{.Effective}} (规则)</span>{{end}}</td>
 <td class="mono">{{.Dec.Basis}}</td>
 <td>{{.Dec.Rationale}}</td>
</tr>{{end}}
</table>

<h2>依赖图有效性（本版本为什么有效/为什么重算）</h2>
<table>
<tr><th>制品</th><th>对象身份</th><th>状态</th><th>理由</th></tr>
{{range $name, $a := .Artifacts}}
<tr><td>{{$name}}</td><td class="id">{{$a.ObjectID}}</td><td>{{$a.Status}}</td><td>{{$a.Reason}}</td></tr>
{{end}}
</table>

{{if .Conflicts}}
<h2>待解决冲突</h2>
{{range .Conflicts}}{{if eq .Status "open"}}
<div class="card">冲突 <span class="id">{{.ID}}</span>：基线 <span class="id">{{.Base}}</span> 上出现两个候选，
<a href="/flow?id=">{{/* */}}</a>
<a href="/branches">去分支比较页选择继续哪一版 →</a></div>
{{end}}{{end}}{{end}}
{{template "footer"}}{{end}}
`
