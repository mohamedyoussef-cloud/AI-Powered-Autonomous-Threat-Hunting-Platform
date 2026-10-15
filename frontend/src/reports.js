/* Hunt report -> PDF. Input is the JSON from GET /campaigns/{id}/report?format=json.
   To change what the report contains, edit the sections below; nothing else depends on this file. */
const A=s=>String(s??"").replace(/[–—]/g,"-").replace(/[’‘]/g,"'").replace(/[“”]/g,'"').replace(/→/g,"->").replace(/…/g,"...").replace(/[^\x09\x0A\x20-\xFF]/g,"?");
const C={g:[80,121,116],t:[31,42,37],m:[107,122,114],l:[226,216,198],bg:[244,236,221],bad:[148,95,104],ok:[80,119,101],w:[255,255,255]};

export function reportFileName(m){return `hunt-report-CMP-${m.campaign.id}.pdf`}

export async function buildPdf(m){
  const {jsPDF}=await import("jspdf");
  const d=new jsPDF({unit:"pt",format:"a4"}),W=595,H=842,M=44,CW=W-2*M;
  let y=M+22;
  const color=c=>d.setTextColor(...c), fill=c=>d.setFillColor(...c), draw=c=>d.setDrawColor(...c);
  const need=h=>{if(y+h>H-56){d.addPage();y=M+22}};
  const text=(t,{size=9.5,bold=false,c=C.t,x=M,w=CW,gap=3,font="helvetica"}={})=>{d.setFont(font,bold?"bold":"normal");d.setFontSize(size);color(c);const ls=d.splitTextToSize(A(t),w);const lh=size*1.38;need(ls.length*lh);ls.forEach(l=>{d.text(l,x,y+size);y+=lh});y+=gap};
  const h1=t=>{need(40);y+=8;fill(C.g);d.rect(M,y,3,16,"F");d.setFont("helvetica","bold");d.setFontSize(13);color(C.t);d.text(A(t),M+10,y+12);y+=26};
  const table=(cols,rows,widths)=>{const tw=widths.reduce((a,b)=>a+b,0),ws=widths.map(x=>x/tw*CW);
    const row=(cells,head)=>{d.setFont("helvetica",head?"bold":"normal");d.setFontSize(8.2);const ls=cells.map((c,i)=>d.splitTextToSize(A(c),ws[i]-8));const h=Math.max(...ls.map(l=>l.length))*11+8;need(h);
      if(head){fill(C.bg);d.rect(M,y,CW,h,"F")}else{draw(C.l);d.line(M,y+h,M+CW,y+h)}
      let x=M;ls.forEach((l,i)=>{color(head?C.m:C.t);l.forEach((s,k)=>d.text(s,x+4,y+10+k*11));x+=ws[i]});y+=h};
    row(cols,true);rows.forEach(r=>row(r,false));y+=8};
  const kpis=items=>{const w=(CW-10*(items.length-1))/items.length;need(62);items.forEach(([l,v,c],i)=>{const x=M+i*(w+10);fill(C.bg);d.roundedRect(x,y,w,52,8,8,"F");fill(c||C.g);d.rect(x,y+10,3,32,"F");d.setFont("helvetica","normal");d.setFontSize(7.5);color(C.m);d.text(A(l).toUpperCase(),x+12,y+18);d.setFont("helvetica","bold");d.setFontSize(18);color(C.t);d.text(A(v),x+12,y+40)});y+=64};

  // ---- cover ----
  fill(C.g);d.rect(0,0,W,150,"F");
  d.setFont("helvetica","bold");d.setFontSize(9);color(C.w);d.text("THREATHUNT  |  HUNT REPORT",M,52);
  d.setFontSize(24);const tl=d.splitTextToSize(A(m.campaign.name||"Campaign"),CW);d.text(tl.slice(0,2),M,88);
  d.setFont("helvetica","normal");d.setFontSize(9.5);
  d.text(A(`CMP-${m.campaign.id}  |  ${String(m.campaign.status||"").toUpperCase()}  |  ${m.campaign.target_platform||"platform n/a"}  |  Generated ${(m.generated_at||"").slice(0,16).replace("T"," ")} UTC`),M,132);
  y=176;
  if(m.campaign.description)text(m.campaign.description,{c:C.m,gap:10});

  // ---- 1 executive summary ----
  const s=m.summary||{};
  h1("1. Executive summary");
  kpis([["Campaign risk",m.campaign.risk_score??0,C.bad],["Findings",s.findings??0,C.g],["High risk",s.high_risk??0,C.bad],["Pending review",s.pending_review??0,C.m]]);
  kpis([["Hypotheses",s.hypotheses??0],["Rules",`${s.executable_rules??0}/${s.rules??0}`],["Events scanned",s.events_scanned??0],["Hits",s.hits??0]]);
  text(s.findings?`The hunt matched ${s.hits} event(s) across ${s.executions} execution(s) and produced ${s.findings} finding(s), ${s.high_risk} rated high risk. ${s.pending_review} finding(s) still await an analyst decision.`:`The hunt executed ${s.executions} rule(s) over ${s.events_scanned} event(s) and produced no findings. This is not evidence of absence; see telemetry coverage.`,{gap:8});

  // ---- 2 hypotheses ----
  h1("2. Hunt hypotheses");
  if(!(m.hypotheses||[]).length)text("No hypotheses were linked to this campaign.",{c:C.m});
  (m.hypotheses||[]).forEach(h=>{text(`${h.technique_id}  ${h.technique_name||""}`,{bold:true,size:10,gap:1});text(h.hypothesis_text||"-",{gap:2});
    if(h.detection_objective)text("Detection objective: "+h.detection_objective,{c:C.m,size:8.8,gap:2});
    (h.known_limitations||[]).forEach(x=>text("- "+x,{c:C.m,size:8.5,gap:0}));y+=6});

  // ---- 3 rules ----
  h1("3. Detection rules");
  table(["Rule","Source","Lifecycle","Executable"],(m.rules||[]).map(r=>[r.title,`${r.source||""}${r.source_rule_id?" ("+String(r.source_rule_id).slice(0,8)+")":""}`,r.lifecycle,r.executable?"yes":"NO"]),[4,2.4,1.4,1.1]);

  // ---- 4 execution ----
  h1("4. Execution");
  table(["Rule","Connector","Status","Scanned","Hits","ms"],(m.executions||[]).map(e=>[e.rule,e.connector,e.status,e.events_scanned,e.hits,e.duration_ms]),[4,1.6,1.4,1.2,0.8,0.8]);
  const q=(m.executions||[]).find(e=>e.query);
  if(q){text(`Compiled query (${q.connector})`,{bold:true,size:9,gap:2});text(q.query.split("\n").slice(0,18).join("\n"),{font:"courier",size:7.8,c:C.m,gap:8})}

  // ---- 5 findings ----
  h1(`5. Findings (${(m.findings||[]).length})`);
  if(!(m.findings||[]).length)text("No rule matched the available telemetry in this run.",{c:C.m});
  (m.findings||[]).forEach(f=>{need(80);text(`${f.finding_id}  -  ${f.rule_title||""}`,{bold:true,size:10,gap:1});
    text(`Risk ${f.risk_score??"-"} (${f.label||"-"})  |  Route: ${f.route||"-"}  |  Analyst verdict: ${f.analyst_verdict||"pending"}`,{size:8.8,c:f.label==="high"?C.bad:C.m,gap:1});
    text(`ATT&CK: ${Array.isArray(f.techniques) ? f.techniques.join(", ") : (typeof f.techniques === "string" ? f.techniques : f.techniques && typeof f.techniques === "object" ? Object.values(f.techniques).join(", ") : "-")}  |  Hosts: ${Array.isArray(f.hosts) ? f.hosts.join(", ") : (typeof f.hosts === "string" ? f.hosts : "-")}  |  Case: ${f.case_id||"-"}`,{size:8.5,c:C.m,gap:2});
    if(f.narrative)text(f.narrative,{gap:2});
    if((f.top_factors||[]).length)text("Why this score: "+f.top_factors.map(x=>`${x.factor} (${x.impact>0?"+":""}${x.impact})`).join(", "),{size:8.5,c:C.m,gap:2});y+=6});

  // ---- 6 analyst decisions ----
  h1("6. Analyst decisions");
  const vc={};(m.findings||[]).forEach(f=>{const v=f.analyst_verdict||"pending";vc[v]=(vc[v]||0)+1});
  table(["Verdict","Findings"],Object.entries(vc).map(([k,v])=>[k,v]),[3,1]);

  // ---- 7 timeline ----
  h1("7. Timeline");
  (m.timeline||[]).slice(0,80).forEach(e=>text(`${e.time}  [${e.stage}]  ${e.message}`,{size:8.3,gap:0,c:C.m}));

  // ---- footer on every page ----
  const n=d.getNumberOfPages();
  for(let i=1;i<=n;i++){d.setPage(i);draw(C.l);d.line(M,H-40,W-M,H-40);d.setFont("helvetica","normal");d.setFontSize(7.5);color(C.m);
    d.text(A(`ThreatHunt  |  CMP-${m.campaign.id}  |  Confidential`),M,H-26);d.text(`Page ${i} of ${n}`,W-M,H-26,{align:"right"})}
  return d;
}
export async function downloadPdf(m){const d=await buildPdf(m);d.save(reportFileName(m))}
