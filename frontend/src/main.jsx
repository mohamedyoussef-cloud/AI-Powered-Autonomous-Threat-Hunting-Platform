import {downloadPdf} from "./reports.js";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";

const API = "./api";
const DEMO_PASSWORD = "threathunt";
const DEMO_USERS = {
  "monitor@enterprise.local": { name: "Security Monitor", role: "Monitor", permissions: ["view"] },
  "analyst@enterprise.local": { name: "Threat Hunter", role: "Analyst", permissions: ["view", "investigate", "create", "validate"] },
  "admin@enterprise.local": { name: "Sohila Mahmoud", role: "Administrator", permissions: ["*"] },
};

const FALLBACK_CAMPAIGNS = [
  { id: 2048, name: "Suspicious PowerShell Activity", status: "running", progress: 78, description: "Detect PowerShell-based execution and encoded commands", target_platform: "windows", total_hypotheses: 4, total_rules: 7, total_findings: 12, risk_score: 82, techniques: ["T1059.001","T1059","T1105"] },
  { id: 2047, name: "Credential Access Sweep", status: "completed", progress: 100, description: "Identify credential dumping and LSASS access", target_platform: "windows", total_hypotheses: 3, total_rules: 5, total_findings: 8, risk_score: 76, techniques: ["T1003","T1003.001"] },
  { id: 2043, name: "Lateral Movement Baseline", status: "draft", progress: 0, description: "Detect remote service and SMB movement", target_platform: "windows", total_hypotheses: 2, total_rules: 2, total_findings: 0, risk_score: 18, techniques: ["T1021","T1021.002"] },
];

const FALLBACK_FINDINGS = [
  { finding_id:"F-8821", label:"high", verification_status:"unverified", rule_id:"SIGMA-PS-001", rule_title:"PowerShell Encoded Command", risk_score:92, source_dataset:"evtx", time_start:"2026-09-05 10:42:18", time_end:"2026-09-05 10:42:20", attack_technique_ids:["T1059.001"], case_id:"CASE-2048", hosts:["WIN-CLIENT-01"], users:["svc-backup"], processes:["powershell.exe -enc ..."], narrative:"Encoded PowerShell execution matched a high-confidence detection.", threat_probability:.91, event_references:["EVTX-000184"] },
  { finding_id:"F-8818", label:"medium", verification_status:"unverified", rule_id:"SIGMA-PS-002", rule_title:"PowerShell Download Cradle", risk_score:67, source_dataset:"evtx", time_start:"2026-09-05 10:31:04", time_end:"2026-09-05 10:31:09", attack_technique_ids:["T1059.001","T1105"], case_id:"CASE-2048", hosts:["WIN-CLIENT-03"], users:["analyst"], processes:["WINWORD.EXE → powershell.exe"], narrative:"Office spawned PowerShell with network retrieval behavior.", threat_probability:.68, event_references:["EVTX-000176"] },
  { finding_id:"F-8801", label:"high", verification_status:"confirmed", rule_id:"SIGMA-CA-031", rule_title:"LSASS Memory Access", risk_score:95, source_dataset:"evtx", time_start:"2026-09-05 09:12:33", time_end:"2026-09-05 09:12:36", attack_technique_ids:["T1003.001"], case_id:"CASE-2047", hosts:["WIN-DC-01"], users:["SYSTEM"], processes:["rundll32.exe"], narrative:"Credential access behavior targeting LSASS memory.", threat_probability:.96, event_references:["EVTX-000122"] },
  { finding_id:"F-8799", label:"low", verification_status:"dismissed", rule_id:"SIGMA-LM-014", rule_title:"Remote Service Execution", risk_score:31, source_dataset:"bots", time_start:"2026-09-05 08:47:20", time_end:"2026-09-05 08:47:22", attack_technique_ids:["T1021"], case_id:"CASE-2043", hosts:["WIN-CLIENT-08"], users:["admin"], processes:["services.exe"], narrative:"Remote service execution pattern observed in baseline traffic.", threat_probability:.29, event_references:["BOTS-00044"] },
];

const FALLBACK_RULES = [
  { rule_id:"SIGMA-PS-001", title:"PowerShell Encoded Command", level:"high", status:"active", validation_status:"validated", technique_ids:["T1059.001"], description:"Detects encoded PowerShell execution." },
  { rule_id:"SIGMA-CA-031", title:"LSASS Memory Access", level:"high", status:"active", validation_status:"validated", technique_ids:["T1003.001"], description:"Detects suspicious access to LSASS memory." },
  { rule_id:"SIGMA-PS-002", title:"PowerShell Download Cradle", level:"medium", status:"active", validation_status:"validated", technique_ids:["T1059.001","T1105"], description:"Detects PowerShell retrieval behavior." },
];

const FALLBACK_TECHNIQUES = [
  { attack_id:"T1059.001", name:"PowerShell", tactics:["Execution"], rule_count:7 },
  { attack_id:"T1003.001", name:"LSASS Memory", tactics:["Credential Access"], rule_count:5 },
  { attack_id:"T1105", name:"Ingress Tool Transfer", tactics:["Command and Control"], rule_count:4 },
  { attack_id:"T1021.002", name:"SMB / Windows Admin Shares", tactics:["Lateral Movement"], rule_count:2 },
  { attack_id:"T1053.005", name:"Scheduled Task/Job: Scheduled Task", tactics:["Execution","Persistence"], rule_count:0 },
];

const GREETINGS = ["Welcome","مرحبًا","Bonjour","Hola","Ciao","Hallo","Olá","こんにちは","안녕하세요","你好","Здравствуйте","Namaste","สวัสดี","Bienvenue","Bienvenido","Willkommen","Bem-vindo","ようこそ","환영합니다","أهلاً بك"];

async function api(path, options={}) {
  let token="";
  try{ token=JSON.parse(localStorage.getItem("threathunt_session")||"null")?.token||""; }catch{}
  const res = await fetch(API + path, { ...options, headers: { "Content-Type":"application/json", ...(token?{Authorization:`Bearer ${token}`}:{}), ...(options.headers||{}) } });
  if (res.status === 401 && token && !path.startsWith("/auth/login")) {
    localStorage.removeItem("threathunt_session");
    window.dispatchEvent(new Event("th-session-expired"));
  }

  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) {
        message = typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail);
      } else {
        message = JSON.stringify(body);
      }
    } catch {
      const text = await res.text();
      if (text) message = text;
    }
    throw new Error(message);
  }

  return res.status === 204 ? null : res.json();
}

function Icon({children}) { return <span className="icon">{children}</span>; }
function initials(name="TH") { return name.split(" ").map(x=>x[0]).slice(0,2).join("").toUpperCase(); }
function pct(v) { return `${Math.round((Number(v)||0)*100)}%`; }
function safe(v) { return v ?? "—"; }

function Greeting() {
  const [i,setI] = useState(0);
  useEffect(()=>{ const t=setInterval(()=>setI(x=>(x+1)%GREETINGS.length),1600); return()=>clearInterval(t); },[]);
  return <div className="greeting"><span key={i}>{GREETINGS[i]}</span></div>;
}

function Login({onLogin, theme, setTheme}) {
  const [email,setEmail]=useState("analyst@enterprise.local");
  const [password,setPassword]=useState("threathunt");
  const [error,setError]=useState("");
  const [demo,setDemo]=useState(false);
  const [busy,setBusy]=useState(false);
  const submit=async e=>{
    e.preventDefault();
    setBusy(true);setError("");
    try{
      const r=await api("/auth/login",{method:"POST",body:JSON.stringify({email:email.trim(),password})});
      onLogin({...r.user,token:r.access_token});
    }catch(err){
      setError(/HTTP 401|Invalid/i.test(err.message)?"We could not verify this account. Check your email and password.":`Sign-in failed: ${err.message}`);
    }finally{setBusy(false)}
  };
  const useDemo=(email)=>{setEmail(email);setPassword(DEMO_PASSWORD);setDemo(false);setError("");};
  return <div className="loginPage">
    <div className="loginShell">
      <section className="loginCard">
        <div className="brandLine"><div className="logo">TH</div><div><b>ThreatHunt</b><small>Security Operations Platform</small></div></div>
        <Greeting/>
        <div className="loginEyebrow">SECURITY OPERATIONS PLATFORM</div>
        <h1>See the signal.<br/><em>Understand the threat.</em></h1>
        <p className="loginLead">A connected workspace for ATT&CK intelligence, hypotheses, detections, campaigns and evidence.</p>
        <form onSubmit={submit} className="loginForm">
          <label>Work email<input type="email" value={email} onChange={e=>{setEmail(e.target.value);setError("")}} autoComplete="username" required/></label>
          <label>Password<input type="password" value={password} onChange={e=>{setPassword(e.target.value);setError("")}} autoComplete="current-password" required/></label>
          {error && <div className="errorBox">{error}</div>}
          <button className="primary full" type="submit">Enter ThreatHunt <span>→</span></button>
        </form>
        <div className="loginTools"><span>● Secure account session</span><button onClick={()=>setTheme(theme==="dark"?"light":"dark")}>{theme==="dark"?"☼ Light":"◐ Dark"}</button></div>
        <details className="demoAccess" open={demo} onToggle={e=>setDemo(e.currentTarget.open)}>
          <summary>Demo access <span>Administrator · Analyst · Monitor</span></summary>
          <div>{Object.entries(DEMO_USERS).map(([mail,u])=><div className="demoRow" key={mail}><div><b>{u.role}</b><code>{mail}</code><code>password: {DEMO_PASSWORD}</code></div><button onClick={()=>useDemo(mail)}>Use account</button></div>)}</div>
        </details>
        <div className="loginNote">Role and permissions are derived from the authenticated account. No role is selected at login.</div>
      </section>
      <section className="loginVisual">
        <div className="visualTop"><span>● THREAT INTELLIGENCE FABRIC</span><span>LIVE WORKFLOW</span></div>
        <div className="visualCopy"><small>FROM SIGNAL TO EVIDENCE</small><h2>Every decision<br/><span>has a lineage.</span></h2><p>Follow the reasoning chain behind every hunt.</p></div>
        <div className="network">
          {["ATT&CK","HYPOTHESIS","CAMPAIGN","DETECTION","FINDING"].map((x,i)=><div key={x} className={`netNode n${i+1}`}><small>0{i+1}</small><b>{x}</b><span>{["Knowledge","Reasoning","Orchestration","Signal logic","Evidence"][i]}</span></div>)}
          <i className="pulse p1"/><i className="pulse p2"/><i className="pulse p3"/>
        </div>
        <div className="visualQuote">“ Turn fragmented security signals into decisions your team can defend.”</div>
        <div className="visualFooter">ATT&CK <i/> HYPOTHESIS <i/> DETECTION <i/> HUNT <i/> EVIDENCE</div>
      </section>
    </div>
  </div>;
}

function PageHeader({eyebrow,title,sub,actions}) {
  return <div className="pageHeader"><div><small>{eyebrow}</small><h1>{title}</h1><p>{sub}</p></div>{actions&&<div className="headerActions">{actions}</div>}</div>;
}

function Metric({label,value,meta,tone="green",onClick}) {
  return <button className={`metric ${tone}`} onClick={onClick}><small>{label}</small><strong>{safe(value)}</strong><span>{meta}</span></button>;
}

function Flow({items}) { return <div className="flow">{items.map((x,i)=><React.Fragment key={x}><div><small>0{i+1}</small><b>{x}</b></div>{i<items.length-1&&<span>→</span>}</React.Fragment>)}</div>; }

function Overview({role,go,open}) {
  const monitor=role==="Monitor";
  const [campaigns,setCampaigns]=useState([]);
  const [findings,setFindings]=useState([]);
  const [coverage,setCoverage]=useState(null);
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    let alive=true;
    Promise.all([
      api("/campaigns"),
      api("/findings?page=1&page_size=100"),
      api("/attack/coverage"),
    ]).then(([c,f,cv])=>{
      if(!alive)return;
      setCampaigns(Array.isArray(c)?c:[]);
      setFindings(Array.isArray(f?.items)?f.items:[]);
      setCoverage(cv || null);
    }).catch(()=>{
      if(!alive)return;
      setCampaigns([]);
      setFindings([]);
    }).finally(()=>{
      if(alive)setLoading(false);
    });
    return()=>{alive=false};
  },[]);

  const activeCampaigns=campaigns.filter(c=>c.status==="running");
  const activeCampaign=activeCampaigns[0]||null;
  const findingTotal=findings.length;
  const coveragePct=Number(coverage?.coverage_pct||0);
  const coveredTechniques=Number(coverage?.total_covered||0);
  const totalTechniques=Number(coverage?.total_active_techniques||0);
  const priorityFindings=[...findings]
    .sort((a,b)=>(b.risk_score||0)-(a.risk_score||0))
    .slice(0,5);

  return <><PageHeader
    eyebrow="COMMAND CENTER"
    title={monitor?"Monitoring Overview":"SOC Command Center"}
    sub={monitor
      ?"Read-only operational visibility across campaigns, findings and detection posture."
      :"A decision-oriented view of active investigations, detection health and attack coverage."
    }
    actions={<button className="ghost" onClick={()=>go("hypotheses")}>Explore reasoning →</button>}
  />

  <div className="metrics">
    <Metric
      label="Campaigns"
      value={campaigns.length}
      meta={`${activeCampaigns.length} active · ${campaigns.filter(c=>c.status==="completed").length} completed`}
      onClick={()=>go("campaigns")}
    />
    <Metric
      label="Findings"
      value={findingTotal}
      meta={`${findingTotal} finding${findingTotal===1?"":"s"} in workspace`}
      tone="pink"
      onClick={()=>go("findings")}
    />
    <Metric
      label="ATT&CK coverage"
      value={`${coveragePct.toFixed(2)}%`}
      meta={`${coveredTechniques} of ${totalTechniques} active techniques`}
      tone="blue"
      onClick={()=>go("attack")}
    />
    <Metric
      label="Rules validated"
      value="—"
      meta="Validation metric not exposed by the backend"
      onClick={()=>go("detections")}
    />
  </div>

  <div className="socGrid">
    <section className="panel">
      <PanelTitle title="Threat posture" sub="Current operational signal across the workspace"/>
      <div className="posture">
        <div className="ring"><strong>{Math.round(coveragePct)}</strong><span>POSTURE</span></div>
        <div className="postureLegend">
          <div><i className="dot green"/>Covered <b>{coveredTechniques}</b></div>
          <div><i className="dot blue"/>Active techniques <b>{totalTechniques}</b></div>
          <div><i className="dot pink"/>Uncovered <b>{Math.max(totalTechniques-coveredTechniques,0)}</b></div>
        </div>
      </div>
    </section>

    <section className="panel">
      <PanelTitle
        title="Active investigation"
        sub={activeCampaign?"The campaign currently consuming attention":"No campaign is currently running"}
      />
      {activeCampaign
        ? <div className="investCard" onClick={()=>open({type:"campaign",data:activeCampaign})}>
            <div className="status live">{String(activeCampaign.status||"running").toUpperCase()}</div>
            <h3>{activeCampaign.name}</h3>
            <p>{activeCampaign.description||"Active campaign investigation"}</p>
            <div className="progress"><i style={{width:`${activeCampaign.progress||0}%`}}/></div>
            <div className="miniStats">
              <span><b>{activeCampaign.total_hypotheses||0}</b> hypotheses</span>
              <span><b>{activeCampaign.total_rules||0}</b> rules</span>
              <span><b>{activeCampaign.total_findings||0}</b> findings</span>
            </div>
          </div>
        : <div className="emptyState">
            <b>No active campaign</b>
            <span>Campaign activity will appear here when a campaign is running.</span>
            <button className="linkBtn" onClick={()=>go("campaigns")}>Open campaigns →</button>
          </div>
      }
    </section>
  </div>

  <section className="panel">
    <PanelTitle
      title="Operational lineage"
      sub="The platform's core orchestration relationship"
      action={<button className="linkBtn" onClick={()=>go("attack")}>Open intelligence map →</button>}
    />
    <div className="lineageLarge">
      <Flow items={["ATT&CK","Hypothesis","Campaign","Detection","Finding"]}/>
      <div className="lineageCaption">
        Knowledge informs reasoning. Reasoning creates an operation. Operations produce detections and evidence.
      </div>
    </div>
  </section>

  <section className="panel">
    <PanelTitle
      title="Priority findings"
      sub={loading?"Loading findings…":`${findingTotal} finding${findingTotal===1?"":"s"} currently available`}
    />
    <div className="findingTable">
      {priorityFindings.length
        ? priorityFindings.map(f=>
            <FindingRow key={f.finding_id} f={f} onClick={()=>open({type:"finding",data:f})}/>
          )
        : <div className="emptyState">
            <b>No findings available</b>
            <span>No hunt evidence has been returned by the backend.</span>
          </div>
      }
    </div>
  </section>
  <Insights campaigns={campaigns} findings={findings}/>
  </>;
}
function PanelTitle({title,sub,action}) {
  return <div className="panelTitle">
    <div><b>{title}</b><small>{sub}</small></div>
    {action}
  </div>;
}

function useProviders(){
  const [items,setItems]=useState(null);
  useEffect(()=>{api("/generator/providers").then(x=>setItems(x.items||[])).catch(()=>setItems([]))},[]);
  return items;
}

function ProviderPicker({value,onChange,allowAuto=false,compact=false}) {
  const providers=useProviders();
  if(providers===null)return <div className="muted">Loading detection sources…</div>;
  const opts=[...(allowAuto?[{id:"auto",label:"Automatic",available:true,description:"Corpus rules first, keyword template only when none exists.",kind:"auto"}]:[]),...providers];
  return <div className={`providerPicker${compact?" compact":""}`}>
    {opts.map(p=>{
      const on=value===p.id, off=!p.available;
      return <button type="button" key={p.id} disabled={off} aria-disabled={off} className={`providerCard${on?" on":""}${off?" off":""}`} onClick={()=>!off&&onChange(p.id)}>
        <span className="providerHead"><b>{p.label}</b><span className={`tag ${off?"":"active"}`}>{off?"not connected":p.kind}</span></span>
        <small>{p.description}</small>
        {off&&<small className="providerReason">{p.reason}</small>}
      </button>;
    })}
    <small className="muted providerNote">Every source passes the same validation gate before a rule can run.</small>
  </div>;
}

function SynthesisCard() {
  const providers=useProviders();
  return <section className="panel"><PanelTitle title="Detection synthesis" sub="Where Sigma rules come from before they pass the validation gate"/>
    <div className="readyList">{(providers||[]).map(p=><div className="readyRow" key={p.id}><span className={`dot ${p.available?"green":"pink"}`}/><div><b>{p.label}</b><small>{p.description}</small>{!p.available&&<small>{p.reason}</small>}</div><span className={`tag ${p.available?"active":""}`}>{p.available?"active":"not connected"}</span></div>)}</div>
  </section>;
}

function Campaigns({role,go,open,notify}) {
  const [items,setItems]=useState([]);
  const [filter,setFilter]=useState("all");
  const [q,setQ]=useState("");
  const [builder,setBuilder]=useState(false);
  const [selectedCampaign,setSelectedCampaign]=useState(null);
  const [loading,setLoading]=useState(true);
  const [apiError,setApiError]=useState("");
  const [form,setForm]=useState({name:"",description:"",technique_ids:["T1059.001"],target_platform:"windows",mode:"simulation",rule_source:"auto"});

  useEffect(()=>{
    let alive=true;
    setLoading(true);
    setApiError("");

    api("/campaigns")
      .then(x=>{
        if(!alive)return;

        if(Array.isArray(x)){
          setItems(x);
        }else{
          setItems([]);
          setApiError("Campaign API returned an unexpected response.");
        }
      })
      .catch(()=>{
        if(!alive)return;
        setItems([]);
        setApiError("Campaign data could not be loaded from the backend.");
      })
      .finally(()=>{
        if(alive)setLoading(false);
      });

    return ()=>{alive=false};
  },[]);

  const selectCampaign=(c)=>{
    if(!c?.id)return;
    setSelectedCampaign(c);
  };

  const deleteCampaign=async(c)=>{
    if(role==="Monitor"||!c?.id)return;

    const confirmed=window.confirm(
      `Delete campaign "${c.name||`Campaign #${c.id}`}?"\\n\\nThis action cannot be undone.`
    );

    if(!confirmed)return;

    try{
      await api(`/campaigns/${c.id}`,{method:"DELETE"});
      setItems(items=>items.filter(x=>x.id!==c.id));
      setSelectedCampaign(current=>current?.id===c.id ? null : current);
      notify?.("Campaign deleted.");
    }catch(e){
      notify?.(e?.message||"Campaign could not be deleted.");
    }
  };

  const filtered=items.filter(c=>(filter==="all"||c.status===filter)&&c.name.toLowerCase().includes(q.toLowerCase()));
  const create=async()=>{if(role==="Monitor"||!form.name.trim())return;setLoading(true);try{const c=await api("/campaigns",{method:"POST",body:JSON.stringify({...form,name:form.name.trim(),technique_ids:form.technique_ids})});setItems(x=>[c,...x]);setSelectedCampaign(c);setBuilder(false);notify("Campaign created in the backend.");}catch(e){notify("Campaign API unavailable; no local fake campaign was created.");}finally{setLoading(false)}};
  if(builder) return (
    <CampaignBuilder
      role={role}
      form={form}
      setForm={setForm}
      onClose={()=>setBuilder(false)}
      onCreated={(c)=>{
        setBuilder(false);
        setItems(x=>[c,...x]);
        notify("Campaign created in the backend.");
        setSelectedCampaign(c);
      }}
      loading={loading}
    />
  );
  return <><PageHeader eyebrow="ORCHESTRATION" title="Campaigns" sub="Campaigns are the automation layer connecting hypotheses, rules, hunting and findings." actions={role!=="Monitor"&&<button className="primary" onClick={()=>setBuilder(true)}>＋ Create campaign</button>}/>
    <section className="campaignHero"><div><span className="status live">● AUTOMATION ENGINE ONLINE</span><h2>One campaign. One evidence chain.</h2><p>Every operation keeps a traceable path from threat behavior to observable evidence.</p></div><Flow items={["Hypothesis","Detection","Hunt","Finding"]}/></section>
    <div className="toolbar"><div className="segmented">{["all","running","completed","draft"].map(v=><button key={v} className={filter===v?"active":""} onClick={()=>setFilter(v)}>{v} <b>{v==="all"?items.length:items.filter(x=>x.status===v).length}</b></button>)}</div><input className="search" placeholder="Search campaigns…" value={q} onChange={e=>setQ(e.target.value)}/></div>

    {loading ? (
      <section className="panel">
        <div className="emptyState">Loading campaigns from backend…</div>
      </section>
    ) : apiError ? (
      <section className="panel">
        <div className="emptyState">{apiError}</div>
      </section>
    ) : filtered.length ? (
      <>
        <div className="cards">
          {filtered.map(c=>(
            <CampaignCard
              key={c.id}
              c={c}
              open={()=>selectCampaign(c)}
              role={role}
              onDelete={deleteCampaign}
            />
          ))}
        </div>

        {selectedCampaign && (
          <section className="panel campaignInlineDetails">
            <div className="panelTitle">
              <div>
                <small>CAMPAIGN DETAILS</small>
                <b>{selectedCampaign.name || `Campaign #${selectedCampaign.id}`}</b>
              </div>
              <button
                className="ghost"
                onClick={()=>setSelectedCampaign(null)}
              >
                Close
              </button>
            </div>

            <CampaignObject
              d={selectedCampaign}
              role={role}
              notify={notify}
              openObj={open}
            />
          </section>
        )}
      </>
    ) : (
      <section className="panel">
        <div className="emptyState">No campaigns match the current filters.</div>
      </section>
    )}
  </>;
}

function CampaignBuilder({ onCreated, onClose }) {
  const [featured, setFeatured] = React.useState([]);
  const [allItems, setAllItems] = React.useState([]);
  const [selected, setSelected] = React.useState(null);
  const [form, setForm] = React.useState({
    name: "",
    description: "",
    technique_ids: [],
    target_platform: "Windows",
    mode: "simulation",
    rule_source: "auto",
  });
  const [loading, setLoading] = React.useState(true);
  const [browseAll, setBrowseAll] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const [allLoading, setAllLoading] = React.useState(false);
  const [creating, setCreating] = React.useState(false);
  const [error, setError] = React.useState("");

  const FEATURED = [
    {
      id: "T1059.001",
      label: "PowerShell",
      tactic: "Execution",
      icon: "PS",
    },
    {
      id: "T1003.001",
      label: "LSASS Memory",
      tactic: "Credential Access",
      icon: "LS",
    },
    {
      id: "T1105",
      label: "Ingress Tool Transfer",
      tactic: "Command and Control",
      icon: "IT",
    },
    {
      id: "T1021.002",
      label: "SMB / Admin Shares",
      tactic: "Lateral Movement",
      icon: "SM",
    },
  ];

  React.useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose?.();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  React.useEffect(() => {
    let cancelled = false;

    async function loadFeatured() {
      setLoading(true);
      setError("");

      try {
        const rows = await Promise.all(
          FEATURED.map(async (item) => {
            try {
              const r = await api(
                `/hypotheses/${encodeURIComponent(item.id)}`
              );
              return {
                ...item,
                record: r,
              };
            } catch {
              return null;
            }
          })
        );

        if (!cancelled) {
          setFeatured(rows.filter(Boolean));
        }
      } catch (e) {
        if (!cancelled) setError(e.message || "Failed to load techniques");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    loadFeatured();
    return () => {
      cancelled = true;
    };
  }, []);

  React.useEffect(() => {
    if (!browseAll) return;

    let cancelled = false;

    async function loadAll() {
      setAllLoading(true);
      try {
        const q = search.trim()
          ? `&q=${encodeURIComponent(search.trim())}`
          : "";

        const r = await api(`/hypotheses?page=1&page_size=200${q}`);

        if (!cancelled) {
          setAllItems(r.items || []);
        }
      } catch (e) {
        if (!cancelled) setError(e.message || "Failed to load techniques");
      } finally {
        if (!cancelled) setAllLoading(false);
      }
    }

    const timer = setTimeout(loadAll, 180);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [browseAll, search]);

  function selectTechnique(item) {
    const record = item.record || item;

    setSelected(item);

    setForm((prev) => ({
      ...prev,
      technique_ids: [record.technique_id],
      name:
        prev.name ||
        `${record.technique?.technique_name || item.label} Investigation`,
    }));
  }

  async function createCampaign() {
    if (!form.name.trim()) {
      setError("Campaign name is required.");
      return;
    }

    if (!form.technique_ids.length) {
      setError("Select at least one ATT&CK technique.");
      return;
    }

    setCreating(true);
    setError("");

    try {
      const campaign = await api("/campaigns", {
        method: "POST",
        body: JSON.stringify(form),
      });

      onCreated?.(campaign);
    } catch (e) {
      setError(e.message || "Failed to create campaign");
    } finally {
      setCreating(false);
    }
  }

  const selectedRecord = selected?.record || selected;

  return (
    <div
      className="campaign-builder-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div className="campaign-builder">
        <div className="campaign-builder-head">
          <div>
            <div className="eyebrow">CAMPAIGN BUILDER</div>
            <h2>Create investigation campaign</h2>
            <p>
              Start from a focused ATT&CK investigation path, then follow the
              real Hypothesis → Detection Plan → Rule → Hunt workflow.
            </p>
          </div>

          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        {error && <div className="builder-error">{error}</div>}

        <div className="campaign-builder-body">
          <div className="campaign-builder-main">
            <label className="field-label">Campaign name</label>
            <input
              className="builder-input"
              value={form.name}
              onChange={(e) =>
                setForm((x) => ({ ...x, name: e.target.value }))
              }
              placeholder="e.g. Suspicious PowerShell Activity"
            />

            <label className="field-label">Description</label>
            <textarea
              className="builder-textarea"
              value={form.description}
              onChange={(e) =>
                setForm((x) => ({ ...x, description: e.target.value }))
              }
              placeholder="What are you investigating?"
              rows={3}
            />

            <div className="technique-picker-head">
              <div>
                <label className="field-label">Investigation starting point</label>
                <div className="field-hint">
                  Choose a focused ATT&CK technique to build the campaign around.
                </div>
              </div>

              <button
                type="button"
                className="browse-techniques-btn"
                onClick={() => {
                  setBrowseAll((v) => !v);
                  setSearch("");
                }}
              >
                {browseAll
                  ? "← Back to starting points"
                  : "Browse all ATT&CK techniques →"}
              </button>
            </div>

            {!browseAll ? (
              <div className="featured-techniques">
                {loading ? (
                  <div className="builder-loading">
                    Loading real investigation paths…
                  </div>
                ) : featured.length ? (
                  featured.map((item) => {
                    const record = item.record;
                    const isSelected =
                      selectedRecord?.technique_id === record.technique_id;

                    const dp = record.detection_plan;

                    return (
                      <button
                        type="button"
                        key={item.id}
                        className={`featured-technique ${
                          isSelected ? "selected" : ""
                        }`}
                        onClick={() => selectTechnique(item)}
                      >
                        <span className="technique-icon">{item.icon}</span>

                        <span className="featured-technique-copy">
                          <strong>{item.label}</strong>
                          <small>
                            {item.tactic} · {record.route || "investigation"}
                          </small>
                        </span>

                        <span className="featured-technique-status">
                          {dp ? (
                            <span className="status-pill success">
                              Detection Plan
                            </span>
                          ) : (
                            <span className="status-pill neutral">
                              Hypothesis
                            </span>
                          )}
                        </span>
                      </button>
                    );
                  })
                ) : (
                  <div className="builder-empty">
                    None of the curated starting points are available in the
                    current Phase 3 dataset.
                  </div>
                )}
              </div>
            ) : (
              <div className="all-techniques-browser">
                <div className="technique-search-wrap">
                  <input
                    className="builder-input"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search technique ID or name…"
                    autoFocus
                  />
                </div>

                {allLoading ? (
                  <div className="builder-loading">
                    Loading investigation data…
                  </div>
                ) : (
                  <div className="all-techniques-list">
                    {allItems.map((item) => {
                      const isSelected =
                        selectedRecord?.technique_id === item.technique_id;

                      return (
                        <button
                          type="button"
                          key={item.technique_id}
                          className={`all-technique-row ${
                            isSelected ? "selected" : ""
                          }`}
                          onClick={() =>
                            selectTechnique({ ...item, record: item })
                          }
                        >
                          <span>
                            <strong>{item.technique_id}</strong>
                            <span className="all-technique-name">
                              {item.technique?.technique_name ||
                                "Unnamed technique"}
                            </span>
                          </span>

                          <span className="all-technique-meta">
                            {item.detection_plan ? "Detection Plan" : "Hypothesis"}
                          </span>
                        </button>
                      );
                    })}

                    {!allItems.length && (
                      <div className="builder-empty">
                        No matching techniques found.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {selectedRecord && (
              <div className="selected-technique-panel">
                <div className="selected-technique-title">
                  <div>
                    <span className="eyebrow">SELECTED PATH</span>
                    <h3>
                      {selectedRecord.technique?.technique_name ||
                        selected?.label ||
                        selectedRecord.technique_id}
                    </h3>
                  </div>

                  <span className="technique-id-badge">
                    {selectedRecord.technique_id}
                  </span>
                </div>

                <div className="selected-technique-grid">
                  <div>
                    <span>Hypothesis</span>
                    <strong>
                      {selectedRecord.hypothesis?.hypothesis ||
                        selectedRecord.hypothesis?.hypothesis_text ||
                        "Available"}
                    </strong>
                  </div>

                  <div>
                    <span>Detection Plan</span>
                    <strong>
                      {selectedRecord.detection_plan?.plan_id ||
                        "Not linked"}
                    </strong>
                  </div>

                  {selectedRecord.detection_plan?.detection_intent?.objective && (
                    <div className="selected-technique-wide">
                      <span>Detection objective</span>
                      <strong>
                        {
                          selectedRecord.detection_plan.detection_intent
                            .objective
                        }
                      </strong>
                    </div>
                  )}
                </div>
              </div>
            )}

            <div className="builder-options">
              <div>
                <label className="field-label">Target platform</label>
                <select
                  className="builder-input"
                  value={form.target_platform}
                  onChange={(e) =>
                    setForm((x) => ({
                      ...x,
                      target_platform: e.target.value,
                    }))
                  }
                >
                  <option>Windows</option>
                  <option>Linux</option>
                  <option>macOS</option>
                  <option>Cross-platform</option>
                </select>
              </div>

              <div>
                <label className="field-label">Execution mode</label>
                <select
                  className="builder-input"
                  value={form.mode}
                  onChange={(e) =>
                    setForm((x) => ({ ...x, mode: e.target.value }))
                  }
                >
                  <option value="simulation">Simulation</option>
                  <option value="live">Live</option>
                </select>
              </div>

              <div>
                <label className="field-label">Detection source</label>
                <ProviderPicker allowAuto compact value={form.rule_source} onChange={(v) => setForm((x) => ({ ...x, rule_source: v }))} />
              </div>
            </div>
          </div>

          <aside className="campaign-builder-summary">
            <div className="eyebrow">CAMPAIGN PATH</div>
            <h3>Investigation orchestration</h3>

            <div className="campaign-path">
              <div>
                <b>01</b>
                <span>ATT&CK Technique</span>
              </div>
              <div>
                <b>02</b>
                <span>Hypothesis</span>
              </div>
              <div>
                <b>03</b>
                <span>Detection Plan</span>
              </div>
              <div>
                <b>04</b>
                <span>Detection / Rule</span>
              </div>
              <div>
                <b>05</b>
                <span>Hunt → Finding</span>
              </div>
            </div>

            {selectedRecord && (
              <div className="builder-selection-summary">
                <span>Selected technique</span>
                <strong>{selectedRecord.technique_id}</strong>
                <small>
                  {selectedRecord.technique?.technique_name ||
                    selected?.label}
                </small>
              </div>
            )}

            <div className="builder-actions">
              <button className="secondary-button" onClick={onClose}>
                Cancel
              </button>
              <button
                className="primary-button"
                onClick={createCampaign}
                disabled={creating || !selectedRecord}
              >
                {creating ? "Creating…" : "Create Campaign"}
              </button>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}


const CTX_TABS=[["incidents","Historical incidents","Past confirmed incidents. A matching prior incident is corroborating evidence for a hypothesis."],["assets","Assets","Hosts and services in scope."],["topology","Network topology","Segments, ranges and zones."],["users","User inventory","Accounts and privilege levels."],["organization","Organization context","Priorities, regulations, crown jewels."]];
function parseCsv(t){const rows=[];let r=[],c="",q=false;for(let i=0;i<t.length;i++){const ch=t[i];if(q){if(ch==='"'&&t[i+1]==='"'){c+='"';i++}else if(ch==='"')q=false;else c+=ch}else if(ch==='"')q=true;else if(ch===","){r.push(c);c=""}else if(ch==="\n"||ch==="\r"){if(ch==="\r"&&t[i+1]==="\n")i++;r.push(c);c="";if(r.some(x=>x.trim()))rows.push(r);r=[]}else c+=ch}r.push(c);if(r.some(x=>x.trim()))rows.push(r);return rows}
function InputsContext({role,notify}) {
  const [kind,setKind]=useState("incidents");
  const [data,setData]=useState({items:[],fields:[]});
  const [counts,setCounts]=useState({});
  const [q,setQ]=useState("");
  const [form,setForm]=useState(null);
  const canEdit=role!=="Monitor";
  const load=useCallback(async()=>{try{const [d,c]=await Promise.all([api(`/context/${kind}`),api("/context")]);setData(d);setCounts(c.counts||{})}catch(e){notify?.(e.message)}},[kind]);
  useEffect(()=>{load()},[load]);
  const save=async()=>{try{await api(`/context/${kind}`,{method:"POST",body:JSON.stringify(form)});setForm(null);notify?.("Saved.");load()}catch(e){notify?.(e.message)}};
  const del=async(id)=>{if(!window.confirm("Delete this record?"))return;try{await api(`/context/${kind}/${id}`,{method:"DELETE"});load()}catch(e){notify?.(e.message)}};
  const importCsv=async(file)=>{if(!file)return;const rows=parseCsv(await file.text());if(rows.length<2)return notify?.("CSV needs a header row and at least one record.");const head=rows[0].map(h=>h.trim().toLowerCase());const known=data.fields.filter(f=>head.includes(f));if(!known.length)return notify?.(`No matching columns. Expected: ${data.fields.join(", ")}`);const recs=rows.slice(1).map(r=>Object.fromEntries(known.map(f=>[f,r[head.indexOf(f)]||""])));try{const r=await api(`/context/${kind}`,{method:"POST",body:JSON.stringify(recs)});notify?.(`Imported ${r.added} record(s).`);load()}catch(e){notify?.(e.message)}};
  const rows=(data.items||[]).filter(x=>JSON.stringify(x).toLowerCase().includes(q.toLowerCase()));
  const cur=CTX_TABS.find(t=>t[0]===kind);
  return <>
    <PageHeader eyebrow="ENVIRONMENT" title="Inputs Context" sub="Organizational data kept alongside threat intelligence so hunts reflect your environment."/>
    <div className="campTabs">{CTX_TABS.map(([k,l])=><button key={k} className={kind===k?"active":""} onClick={()=>{setKind(k);setForm(null);setQ("")}}>{l} ({counts[k]||0})</button>)}</div>
    <section className="panel"><PanelTitle title={cur[1]} sub={cur[2]}/>
      <div className="toolbar"><input className="search" placeholder="Filter records…" value={q} onChange={e=>setQ(e.target.value)}/>
        {canEdit&&<><button className="primary" onClick={()=>setForm(Object.fromEntries(data.fields.map(f=>[f,""])))}>+ Add record</button><label className="ghost fileBtn">Import CSV<input type="file" accept=".csv" hidden onChange={e=>{importCsv(e.target.files[0]);e.target.value=""}}/></label></>}</div>
      {form&&<div className="ctxForm">{data.fields.map(f=><label key={f}><small>{f}</small><input value={form[f]} onChange={e=>setForm({...form,[f]:e.target.value})}/></label>)}<div className="headerActions"><button className="primary" onClick={save}>Save</button><button className="ghost" onClick={()=>setForm(null)}>Cancel</button></div></div>}
      {rows.length?<div className="ctxTable"><div className="ctxRow head" style={{gridTemplateColumns:`repeat(${data.fields.length},1fr) 40px`}}>{data.fields.map(f=><span key={f}>{f}</span>)}<span/></div>
        {rows.map(r=><div className="ctxRow" key={r.id} style={{gridTemplateColumns:`repeat(${data.fields.length},1fr) 40px`}}>{data.fields.map(f=><span key={f}>{r[f]||"—"}</span>)}{canEdit?<button className="ghost" title="Delete" onClick={()=>del(r.id)}>×</button>:<span/>}</div>)}</div>
        :<div className="emptyState">No records yet. {canEdit?`Add one or import a CSV with the columns: ${data.fields.join(", ")}.`:""}</div>}
      <small className="muted">Stored in the workspace for the hypothesis engine. Scoring does not consume these inputs yet.</small>
    </section></>;
}


function Reports({role,notify}) {
  const [camps,setCamps]=useState(null);
  const [q,setQ]=useState("");
  const [sel,setSel]=useState(null);
  const [model,setModel]=useState(null);
  const [busy,setBusy]=useState(false);
  useEffect(()=>{api("/campaigns").then(x=>setCamps(Array.isArray(x)?x:[])).catch(()=>setCamps([]))},[]);
  const load=async(c)=>{setSel(c);setModel(null);setBusy(true);try{setModel(await api(`/campaigns/${c.id}/report?format=json`))}catch(e){notify?.(e.message)}finally{setBusy(false)}};
  const pdf=async(c)=>{try{setBusy(true);const m=model&&sel?.id===c.id?model:await api(`/campaigns/${c.id}/report?format=json`);await downloadPdf(m);notify?.("PDF downloaded.")}catch(e){notify?.(e.message||"PDF could not be created.")}finally{setBusy(false)}};
  const list=(camps||[]).filter(c=>(c.name||"").toLowerCase().includes(q.toLowerCase()));
  return <>
    <PageHeader eyebrow="DELIVERABLES" title="Reports" sub="Hunt reports with campaign details, hypotheses, rules, executions, findings, risk and analyst decisions. Export as PDF."/>
    <div className="grid reportsGrid">
      <section className="panel"><PanelTitle title="Campaign reports" sub={camps===null?"Loading…":`${list.length} campaign(s)`}/>
        <div className="toolbar"><input className="search" placeholder="Search campaigns…" value={q} onChange={e=>setQ(e.target.value)}/></div>
        {list.length?<div className="reportList">{list.map(c=><div key={c.id} className={`reportItem ${sel?.id===c.id?"selected":""}`}>
          <button className="reportMain" onClick={()=>load(c)}><span className={`status ${c.status}`}>{c.status}</span><b>{c.name}</b><small>CMP-{c.id} · {c.total_findings||0} findings · risk {c.risk_score||0}</small></button>
          <button className="primary" disabled={busy} onClick={()=>pdf(c)}>PDF ↓</button></div>)}</div>
          :<div className="emptyState">{camps===null?"Loading…":"No campaigns yet. Create and run a campaign to generate its report."}</div>}
      </section>
      <section className="panel reportPreview"><PanelTitle title="Preview" sub={sel?`CMP-${sel.id}`:"Select a campaign to preview its report"} action={sel&&model&&<div className="headerActions"><button className="primary" disabled={busy} onClick={()=>pdf(sel)}>Download PDF</button><button className="ghost" onClick={()=>downloadReport(sel.id).catch(e=>notify?.(e.message))}>Markdown</button></div>}/>
        {busy&&!model?<div className="emptyState">Building report…</div>:model?<ReportView m={model}/>:<div className="emptyState">The preview shows exactly what the PDF contains.</div>}
      </section>
    </div></>;
}

const INS_TABS=[["exec","Executive"],["risk","Risk"],["fp","False positives"],["siem","SIEM executions"]];
function Insights({campaigns,findings}) {
  const [tab,setTab]=useState("exec");
  const [execs,setExecs]=useState(null);
  useEffect(()=>{if(tab!=="siem"||execs)return;Promise.all((campaigns||[]).slice(0,15).map(c=>api(`/campaigns/${c.id}/executions`).then(x=>x.items||[]).catch(()=>[]))).then(a=>setExecs(a.flat()))},[tab,campaigns]);
  const bars=(rows,tone)=>{const mx=Math.max(1,...rows.map(r=>r[1]));return <div className="insBars">{rows.map(([l,v,t])=><div key={l}><span>{l}</span><i><u style={{width:`${v/mx*100}%`,background:`var(--${t||tone||"green"})`}}/></i><b>{v}</b></div>)}</div>};
  const cnt=(arr,fn)=>arr.reduce((a,x)=>{const k=fn(x);a[k]=(a[k]||0)+1;return a},{});
  const risk=cnt(findings,f=>f.label||"unknown"),ver=cnt(findings,f=>f.verification_status||"unverified");
  const avg=campaigns.length?Math.round(campaigns.reduce((a,c)=>a+(c.risk_score||0),0)/campaigns.length):0;
  const fpRate=findings.length?Math.round((ver.dismissed||0)/findings.length*100):0;
  const byConn={};(execs||[]).forEach(e=>{const r=byConn[e.connector]||(byConn[e.connector]={runs:0,ok:0,failed:0,hits:0});r.runs++;if(e.status==="completed")r.ok++;if(e.status==="failed"||e.status==="blocked")r.failed++;r.hits+=e.hits||0});
  return <section className="panel"><PanelTitle title="Operational insights" sub="Executive, risk, false-positive and SIEM execution views"/>
    <div className="campTabs">{INS_TABS.map(([k,l])=><button key={k} className={tab===k?"active":""} onClick={()=>setTab(k)}>{l}</button>)}</div>
    {tab==="exec"&&<><div className="reportKpis">{[["Campaigns",campaigns.length],["Running",campaigns.filter(c=>c.status==="running").length],["Completed",campaigns.filter(c=>c.status==="completed").length],["Avg. campaign risk",avg]].map(([l,v])=><div key={l}><small>{l}</small><b>{v}</b></div>)}</div>{bars(campaigns.map(c=>[c.name,c.risk_score||0,(c.risk_score||0)>70?"pink":"green"]))}</>}
    {tab==="risk"&&(findings.length?bars(["high","medium","low"].map(k=>[k,risk[k]||0,k==="high"?"pink":k==="medium"?"blue":"green"])):<div className="emptyState">No findings yet.</div>)}
    {tab==="fp"&&<><div className="reportKpis">{[["Findings",findings.length],["Dismissed",ver.dismissed||0],["Unverified",ver.unverified||0],["False-positive rate",`${fpRate}%`]].map(([l,v])=><div key={l}><small>{l}</small><b>{v}</b></div>)}</div>{findings.length?bars(Object.entries(ver).map(([k,v])=>[k,v,k==="dismissed"?"blue":"green"])):<div className="emptyState">No findings yet.</div>}</>}
    {tab==="siem"&&(execs===null?<div className="emptyState">Loading executions…</div>:Object.keys(byConn).length?<div className="ctxTable">{[["Connector","Runs","Completed","Failed","Hits"],...Object.entries(byConn).map(([k,r])=>[k,r.runs,r.ok,r.failed,r.hits])].map((r,i)=><div key={i} className={`ctxRow ${i?"":"head"}`} style={{gridTemplateColumns:"2fr repeat(4,1fr)"}}>{r.map((c,j)=><span key={j}>{c}</span>)}</div>)}</div>:<div className="emptyState">No executions yet.</div>)}
  </section>;
}

function CampaignCard({c,open,role,onDelete}) {
  return (
    <div className="card campaignCard" onClick={open}>
      {role!=="Monitor"&&(
        <button
          type="button"
          className="campaignDeleteButton"
          title="Delete campaign"
          aria-label={`Delete ${c.name||"campaign"}`}
          onClick={e=>{
            e.stopPropagation();
            onDelete?.(c);
          }}
        >
          ×
        </button>
      )}

      <div className="cardTop">
        <span className={`status ${c.status}`}>{c.status}</span>
        <code>CMP-{c.id}</code>
      </div>

      <h3>{c.name}</h3>
      <p>{c.description}</p>

      <div className="cardChain">{[["Hypothesis",c.total_hypotheses],["Rule",c.total_rules],["Hunt",["running","hunting","completed"].includes(c.status)?1:0],["Finding",c.total_findings]].map(([l,n],i)=><React.Fragment key={l}>{i>0&&<em className={n?"on":""}/>}<span className={n?"on":""}>{l}</span></React.Fragment>)}</div>
      <div className="progress">
        <i style={{width:`${c.progress||0}%`}}/>
      </div>

      <div className="miniStats">
        <span><b>{c.total_hypotheses||0}</b> hypotheses</span>
        <span><b>{c.total_rules||0}</b> rules</span>
        <span><b>{c.total_findings||0}</b> findings</span>
      </div>

      <div className="cardFooter">
        <span>Risk {c.risk_score||0}</span>
        <span>{role==="Monitor"?"Read only":"Open investigation"} →</span>
      </div>
    </div>
  );
}

function Findings({open}) {
  const [items,setItems]=useState([]);
  const [total,setTotal]=useState(0);
  const [sev,setSev]=useState("all");
  const [status,setStatus]=useState("all");
  const [q,setQ]=useState("");

  useEffect(()=>{
    let alive=true;
    api("/findings?page=1&page_size=100")
      .then(x=>{
        if(!alive)return;
        setItems(Array.isArray(x?.items)?x.items:[]);
        setTotal(Number(x?.total)||0);
      })
      .catch(()=>{
        if(!alive)return;
        setItems([]);
        setTotal(0);
      });
    return()=>{alive=false};
  },[]);

  const filtered=items.filter(f=>
    (sev==="all"||f.label===sev) &&
    (status==="all"||f.verification_status===status) &&
    `${f.finding_id} ${f.rule_title} ${(f.attack_technique_ids||[]).join(" ")}`
      .toLowerCase()
      .includes(q.toLowerCase())
  );

  const openFindings=items.filter(
    x=>!["dismissed","resolved"].includes(x.verification_status)
  ).length;

  const highRisk=items.filter(
    x=>(Number(x.risk_score)||0)>=80
  ).length;

  const confirmed=items.filter(
    x=>x.verification_status==="confirmed"
  ).length;

  const unverified=items.filter(
    x=>x.verification_status==="unverified"
  ).length;

  return <><PageHeader
    eyebrow="INVESTIGATION"
    title="Hunt Findings"
    sub="Investigate evidence, risk and analyst decisions without losing the original event context."
  />

  <div className="metrics">
    <Metric label="Open findings" value={openFindings} meta={`${total} total findings`}/>
    <Metric label="High risk" value={highRisk} meta="Risk score ≥ 80" tone="pink"/>
    <Metric label="Confirmed" value={confirmed} meta="Analyst-confirmed evidence" tone="blue"/>
    <Metric label="Unverified" value={unverified} meta="Needs analyst review"/>
  </div>

  <section className="panel">
    <div className="toolbar">
      <div className="segmented">
        {["all","high","medium","low"].map(x=>
          <button key={x} className={sev===x?"active":""} onClick={()=>setSev(x)}>{x}</button>
        )}
      </div>

      <select value={status} onChange={e=>setStatus(e.target.value)}>
        <option value="all">All statuses</option>
        <option value="unverified">Unverified</option>
        <option value="confirmed">Confirmed</option>
        <option value="dismissed">Dismissed</option>
        <option value="resolved">Resolved</option>
      </select>

      <input
        className="search"
        placeholder="Search ID, rule or technique…"
        value={q}
        onChange={e=>setQ(e.target.value)}
      />
    </div>

    <div className="findingTable">
      {filtered.length
        ? filtered.map(f=>
            <FindingRow
              key={f.finding_id}
              f={f}
              onClick={()=>open({type:"finding",data:f})}
            />
          )
        : <div className="emptyState">
            <b>No findings match the current filters</b>
            <span>The list is backed by the current HuntFinding records.</span>
          </div>
      }
    </div>
  </section>
  </>;
}
function FindingRow({f,onClick}) { return <button className="findingRow" onClick={onClick}><div className={`severity ${f.label}`}>{f.label}</div><div className="findingMain"><b>{f.rule_title}</b><small>{f.finding_id} · {f.rule_id} · {(f.attack_technique_ids||[]).join(" · ")}</small></div><div><small>Risk</small><b>{f.risk_score}</b></div><div><small>Status</small><span className="tag">{f.verification_status}</span></div><span>→</span></button>; }

function Detections({role,open}) {
  const [items,setItems]=useState([]);
  const [q,setQ]=useState("");
  const [page,setPage]=useState(1);
  const [total,setTotal]=useState(0);
  const pageSize=100;

  useEffect(()=>{
    let alive=true;
    api(`/sigma/rules?page=${page}&page_size=${pageSize}`)
      .then(x=>{
        if(!alive)return;
        setItems(Array.isArray(x?.items)?x.items:[]);
        setTotal(Number(x?.total)||0);
      })
      .catch(()=>{
        if(!alive)return;
        setItems([]);
        setTotal(0);
      });
    return()=>{alive=false};
  },[page]);

  const totalPages=Math.max(1,Math.ceil(total/pageSize));
  const filtered=items.filter(r=>
    `${r.rule_id} ${r.title} ${(r.technique_ids||[]).join(" ")}`
      .toLowerCase()
      .includes(q.toLowerCase())
  );

  const first=total===0?0:((page-1)*pageSize)+1;
  const last=Math.min(page*pageSize,total);

  return <>
    <PageHeader
      eyebrow="DETECTION KNOWLEDGE"
      title="Detections"
      sub="Browse the Sigma knowledge base and trace detection logic to ATT&CK techniques."
      actions={role!=="Monitor"&&
        <button
          className="primary"
          onClick={()=>open({type:"generator",data:{}})}
        >
          ＋ Generate rule
        </button>
      }
    />

    <section className="panel detectionsPanel">
      <div className="detectionToolbar">
        <div className="detectionTitle">
          <div className="detectionIcon">Σ</div>
          <div>
            <b>Sigma Knowledge Base</b>
            <span>External detection knowledge mapped into ThreatHunt</span>
          </div>
        </div>

        <div className="detectionControls">
          <span className="detectionCount">{total.toLocaleString()} rules</span>
          <input
            className="search"
            placeholder="Search rules or ATT&CK…"
            value={q}
            onChange={e=>setQ(e.target.value)}
          />
        </div>
      </div>

      <div className="detectionSummary">
        <span>Showing <b>{first}–{last}</b> of <b>{total.toLocaleString()}</b></span>
        <span>Knowledge base · SigmaHQ</span>
      </div>

      <div className="ruleTable detectionRules">
        {filtered.map(r=>{
          const techniques=r.technique_ids||[];
          return <button
            className="ruleRow detectionRuleRow"
            key={r.rule_id}
            onClick={()=>open({type:"rule",data:r})}
          >
            <div className="ruleIdentity">
              <b>{r.title}</b>
              <small>{r.rule_id}</small>
            </div>

            <div className="ruleMappings">
              {techniques.length
                ? techniques.slice(0,3).map(t=><span className="attackChip" key={t}>{t}</span>)
                : <span className="noMapping">No ATT&CK mapping</span>
              }
              {techniques.length>3&&
                <span className="moreMapping">+{techniques.length-3}</span>
              }
            </div>

            <span className={`tag ruleStatus ${r.status||"unknown"}`}>
              {r.status||"unknown"}
            </span>

            <span className={`severity ${r.level||"low"}`}>
              {r.level||"—"}
            </span>

            <span className="ruleArrow">→</span>
          </button>;
        })}

        {!filtered.length&&
          <div className="emptyState">
            No Sigma rules match this search on the current page.
          </div>
        }
      </div>

      <div className="detectionPagination">
        <button
          className="pageButton"
          disabled={page<=1}
          onClick={()=>setPage(p=>Math.max(1,p-1))}
        >
          <span>←</span> Previous
        </button>

        <div className="pageIndicator">
          <b>{page}</b>
          <span>/</span>
          <span>{totalPages}</span>
        </div>

        <button
          className="pageButton"
          disabled={page>=totalPages}
          onClick={()=>setPage(p=>Math.min(totalPages,p+1))}
        >
          Next <span>→</span>
        </button>
      </div>
    </section>
  </>;
}

function Hypotheses({open}) {
  const [items,setItems]=useState([]),[q,setQ]=useState(""),[summary,setSummary]=useState(null);
  useEffect(()=>{api("/hypotheses?page_size=100").then(x=>setItems(x?.items||[])).catch(()=>{});api("/hypotheses/summary").then(setSummary).catch(()=>{})},[]);
  const fallback=[{technique_id:"T1059.001",route:"runtime_hunt",title:"PowerShell download cradle",confidence:.91,required_telemetry:"Process creation + network activity",reasoning:"Encoded PowerShell plus network retrieval is consistent with execution and ingress transfer."},{technique_id:"T1003.001",route:"runtime_hunt",title:"LSASS memory access",confidence:.86,required_telemetry:"Process access events",reasoning:"Access to LSASS memory can indicate credential dumping behavior."},{technique_id:"T1021.002",route:"environment_resolution",title:"SMB administrative share movement",confidence:.64,required_telemetry:"Network + service creation",reasoning:"Remote share and service activity can support lateral movement hypotheses."}];
  const data=items.length?items:fallback, filtered=data.filter(h=>JSON.stringify(h).toLowerCase().includes(q.toLowerCase()));
  return <><PageHeader eyebrow="REASONING LAYER" title="Hypothesis Intelligence Center" sub="The reasoning layer between telemetry, ATT&CK applicability and executable detection plans."/><section className="hypHero"><div><span className="status live">REASONING ENGINE</span><h2>From signal to a defensible hunt</h2><p>Inspect why a hypothesis exists, which telemetry supports it and how it can become a campaign operation.</p></div><Flow items={["Telemetry","Signal","Hypothesis","Applicability","Detection Plan","Campaign"]}/></section>
  <div className="hypMetrics"><Metric label="Processed" value="697" meta="Phase 3 hypothesis records"/><Metric label="Eligible" value="505" meta="Applicable techniques" tone="blue"/><Metric label="Grounded plans" value="505" meta="Detection plans" tone="green"/><Metric label="Baseline ready" value="492" meta="Current readiness" tone="pink"/></div>
  <section className="panel"><div className="toolbar"><input className="search" placeholder="Search hypothesis, technique or route…" value={q} onChange={e=>setQ(e.target.value)}/><span className="engineMeta">{summary?.total||697} records</span></div><div className="hypList">{filtered.map((h,i)=><button className="hypRow" key={(h.technique_id||"h")+i} onClick={()=>open({type:"hypothesis",data:h})}><code>{h.technique_id}</code><div><b>{h.title||h.hypothesis_text||"Behavior hypothesis"}</b><small>{h.reasoning||h.hypothesis_text||"Grounded behavioral reasoning"} </small></div><span>{pct(h.confidence)}</span><span className="tag">{h.route||"route"}</span><span>→</span></button>)}</div></section></>;
}

function Attack({open}) {
  const [items,setItems]=useState(FALLBACK_TECHNIQUES),[q,setQ]=useState("");
  useEffect(()=>{api("/attack/techniques").then(x=>x?.length&&setItems(x)).catch(()=>{})},[]);
  const filtered=items.filter(t=>`${t.attack_id} ${t.name} ${(t.tactics||[]).join(" ")}`.toLowerCase().includes(q.toLowerCase()));
  return <><PageHeader eyebrow="KNOWLEDGE LAYER" title="ATT&CK Intelligence Map" sub="Explore technique coverage, detection depth and relationships to hypotheses, campaigns and findings."/><section className="attackMap"><div className="mapGrid"/><div className="mapCenter"><strong>THREATHUNT</strong><small>INTELLIGENCE FABRIC</small></div>{filtered.slice(0,10).map((t,i)=><button key={t.attack_id} className="attackNode" style={{left:`${12+(i*19)%76}%`,top:`${18+(i*31)%62}%`}} onClick={()=>open({type:"technique",data:t})}><small>{t.attack_id}</small><b>{t.name}</b><span>{t.rule_count||0} rules</span></button>)}</section><section className="panel"><div className="toolbar"><div><b>Technique coverage</b><small>Node size and activity are represented in the intelligence map.</small></div><input className="search" placeholder="Search technique…" value={q} onChange={e=>setQ(e.target.value)}/></div><div className="techTable">{filtered.map(t=><button className="techRow" key={t.attack_id} onClick={()=>open({type:"technique",data:t})}><code>{t.attack_id}</code><div><b>{t.name}</b><small>{(t.tactics||[]).join(" · ")}</small></div><span className={`tag ${t.rule_count?"covered":"gap"}`}>{t.rule_count?"Covered":"Gap"}</span><span>{t.rule_count||0} rules</span><span>→</span></button>)}</div></section></>;
}

function Datasets({role}) {
  const [items,setItems]=useState([]);
  const [selected,setSelected]=useState(null);
  const [adding,setAdding]=useState(false);
  const [busy,setBusy]=useState(false);
  const canEdit=role!=="Monitor";

  const baselineSources=[
    {
      source_id:"EVTX",
      name:"EVTX-ATT&CK-SAMPLES",
      raw_status:"connected",
      enabled:true,
      managed:false,
      file_count:278,
      record_count:null,
      source_type:"EVTX",
      description:"Windows event telemetry mapped to ATT&CK behaviors.",
      health_status:"Connected"
    },
    {
      source_id:"BOTS",
      name:"BOTS v3",
      raw_status:"connected",
      enabled:true,
      managed:false,
      file_count:0,
      record_count:null,
      source_type:"Streaming telemetry",
      description:"Splunk Boss of the SOC telemetry used by the hunting layer.",
      health_status:"Connected"
    }
  ];

  const empty={
    source_id:"",
    name:"",
    source_type:"Custom",
    endpoint:"",
    description:"",
    enabled:true
  };

  const load=async()=>{
    try{
      const x=await api("/source-control");
      const apiItems=x?.items||[];

      // Always preserve the two platform baseline sources.
      const merged=[...baselineSources];

      for(const item of apiItems){
        const idx=merged.findIndex(
          v=>v.source_id===item.source_id
        );

        if(idx>=0){
          merged[idx]={...merged[idx],...item};
        }else{
          merged.push(item);
        }
      }

      setItems(merged);
    }catch{
      setItems(baselineSources);
    }
  };

  useEffect(()=>{load()},[]);

  const openAdd=()=>{
    setSelected(null);
    setForm(empty);
    setAdding(true);
  };

  const openEdit=x=>{
    setSelected(x);
    setForm({...empty,...x});
    setAdding(true);
  };

  const [form,setForm]=useState(empty);

  const save=async()=>{
    if(!form.name.trim()||!canEdit)return;

    setBusy(true);

    try{
      const body={
        ...form,
        name:form.name.trim(),
        source_id:form.source_id?.trim()||undefined
      };

      if(selected){
        await api(
          `/source-control/${encodeURIComponent(selected.source_id)}`,
          {
            method:"PATCH",
            body:JSON.stringify(body)
          }
        );
      }else{
        await api(
          "/source-control",
          {
            method:"POST",
            body:JSON.stringify(body)
          }
        );
      }

      await load();
      setAdding(false);
      setSelected(null);
    }catch(e){
      alert(e.message||"Source could not be saved.");
    }finally{
      setBusy(false);
    }
  };

  const toggle=async x=>{
    if(!canEdit)return;

    try{
      await api(
        `/source-control/${encodeURIComponent(x.source_id)}`,
        {
          method:"PATCH",
          body:JSON.stringify({enabled:!x.enabled})
        }
      );

      await load();
    }catch(e){
      alert("Source status could not be changed.");
    }
  };

  const remove=async x=>{
    if(!canEdit||!x.managed)return;

    if(!window.confirm(
      `Remove ${x.name} from workspace sources?`
    ))return;

    try{
      await api(
        `/source-control/${encodeURIComponent(x.source_id)}`,
        {method:"DELETE"}
      );

      await load();
    }catch(e){
      alert(e.message||"Source could not be removed.");
    }
  };

  return <>
    <PageHeader
      eyebrow="DATA PLANE"
      title="Data Sources"
      sub="Control the telemetry layer from ThreatHunt. Connect, configure, enable or disable workspace-managed sources without losing the platform baseline."
      actions={
        canEdit &&
        <button className="primary" onClick={openAdd}>
          ＋ Add source
        </button>
      }
    />

    <section className="sourceControlBar">
      <div>
        <b>{items.filter(x=>x.enabled!==false).length} sources available</b>
        <span>
          · {items.filter(x=>x.enabled===false).length} disabled
          · {items.filter(x=>x.managed).length} workspace-managed
        </span>
      </div>

      <small>
        Baseline telemetry remains visible and traceable to the platform pipeline.
      </small>
    </section>

    <div className="sourceGrid">
      {items.map(x=>
        <article
          className={`sourceCard ${x.enabled===false?"disabled":""}`}
          key={x.source_id}
        >
          <div className="sourceTop">
            <span className={`status ${x.enabled===false?"draft":"completed"}`}>
              {x.enabled===false
                ? "DISABLED"
                : (x.raw_status||"CONNECTED").replaceAll("_"," ")
              }
            </span>

            <code>{x.source_id}</code>
          </div>

          <h3>{x.name}</h3>

          <p>
            {x.description ||
             x.intended_platform_use ||
             x.health_status ||
             "Telemetry source"}
          </p>

          <div className="sourceMeta">
            <span>
              <b>
                {x.record_count!=null
                  ? Number(x.record_count).toLocaleString()
                  : "—"}
              </b>
              <small>records</small>
            </span>

            <span>
              <b>{x.file_count||0}</b>
              <small>files</small>
            </span>

            <span>
              <b>{x.managed?"Workspace":"Baseline"}</b>
              <small>ownership</small>
            </span>
          </div>

          <div className="sourceActions">
            {canEdit &&
              <button className="ghost" onClick={()=>openEdit(x)}>
                Manage
              </button>
            }

            {canEdit &&
              <button
                className={`toggleBtn ${x.enabled!==false?"on":""}`}
                onClick={()=>toggle(x)}
              >
                {x.enabled!==false?"Enabled":"Disabled"}
              </button>
            }

            {canEdit && x.managed &&
              <button
                className="dangerBtn"
                onClick={()=>remove(x)}
              >
                Remove
              </button>
            }
          </div>
        </article>
      )}
    </div>

    {adding &&
      <div
        className="modalOverlay"
        onMouseDown={e=>{
          if(e.target===e.currentTarget)setAdding(false)
        }}
      >
        <section className="sourceModal">

          <div className="drawerHead">
            <div>
              <small>
                {selected?"SOURCE CONTROL":"NEW SOURCE"}
              </small>

              <h2>
                {selected
                  ? "Manage source"
                  : "Add a telemetry source"}
              </h2>
            </div>

            <button onClick={()=>setAdding(false)}>×</button>
          </div>

          <div className="sourceForm">

            <label>
              Source name
              <input
                autoFocus
                value={form.name}
                onChange={e=>
                  setForm({...form,name:e.target.value})
                }
                placeholder="e.g. Microsoft Defender"
              />
            </label>

            {!selected &&
              <label>
                Source ID
                <input
                  value={form.source_id}
                  onChange={e=>
                    setForm({...form,source_id:e.target.value})
                  }
                  placeholder="e.g. defender_endpoint"
                />
              </label>
            }

            <label>
              Source type
              <select
                value={form.source_type}
                onChange={e=>
                  setForm({...form,source_type:e.target.value})
                }
              >
                <option>Custom</option>
                <option>Splunk</option>
                <option>Elastic</option>
                <option>Microsoft Defender</option>
                <option>Syslog</option>
                <option>EVTX</option>
                <option>REST API</option>
                <option>Streaming telemetry</option>
              </select>
            </label>

            <label>
              Endpoint / location
              <input
                value={form.endpoint||""}
                onChange={e=>
                  setForm({...form,endpoint:e.target.value})
                }
                placeholder="https://… or /path/to/source"
              />
            </label>

            <label>
              Description
              <textarea
                rows="4"
                value={form.description||""}
                onChange={e=>
                  setForm({...form,description:e.target.value})
                }
                placeholder="What telemetry does this source provide?"
              />
            </label>

            <div className="sourceModalFooter">
              <button
                className="ghost"
                onClick={()=>setAdding(false)}
              >
                Cancel
              </button>

              <button
                className="primary"
                disabled={busy||!form.name.trim()}
                onClick={save}
              >
                {busy
                  ? "Saving…"
                  : selected
                    ? "Save changes"
                    : "Add source"}
              </button>
            </div>

          </div>
        </section>
      </div>
    }
  </>;
}

function Pipeline({role,notify}) {
  const [ready,setReady]=useState(null),[conns,setConns]=useState([]),[tel,setTel]=useState(null),[busy,setBusy]=useState(false),[phase,setPhase]=useState(null);
  const load=useCallback(()=>{
    api("/health/ready").then(setReady).catch(()=>setReady(null));
    api("/connectors").then(x=>setConns(x.items||[])).catch(()=>{});
    api("/telemetry/summary").then(setTel).catch(()=>{});
    api("/integration/status").then(setPhase).catch(()=>{});
  },[]);
  useEffect(()=>{load()},[load]);
  const ingest=async()=>{setBusy(true);try{const r=await api("/telemetry/ingest",{method:"POST",body:JSON.stringify({kind:"default_samples"})});notify?.(`Loaded ${r.ingested.reduce((a,x)=>a+x.added,0)} new events${r.errors.length?`, ${r.errors.length} sample(s) failed`:""}.`);load()}catch(e){notify?.(e.message)}finally{setBusy(false)}};
  const c=ready?.checks||{};
  const rows=[
    ["Database",c.database,"Campaign, finding and rule storage"],
    ["Local telemetry",c.telemetry_events>0,`${c.telemetry_events||0} normalized events available to hunt`],
    ["Phase-3 hypotheses",c.phase3_hypotheses,"Hypothesis Engine outputs (falls back to ATT&CK-derived hypotheses when missing)"],
    ["Detection plans",c.detection_plans,"Team detection-plan file"],
    ["Pipeline data root",c.pipeline_data_root,"Data-prep artifacts"],
    ["Splunk connector",c.splunk_configured,"Set SPLUNK_URL and SPLUNK_TOKEN to enable live execution"],
    ["Auth secret rotated",c.auth_secret_changed,"Set THREATHUNT_AUTH_SECRET before any shared deployment"],
  ];
  return <>
    <PageHeader eyebrow="PIPELINE" title="Pipeline Operations" sub="Live readiness of every dependency the hunt pipeline relies on."/>
    <div className="metrics">
      <Metric label="Telemetry events" value={tel?.total_events??"—"} meta="Available to the local backend"/>
      <Metric label="Sources" value={tel?.sources?.length??"—"} meta="Loaded EVTX / JSONL files" tone="blue"/>
      <Metric label="Hosts" value={tel?.hosts?.length??"—"} meta="Distinct hosts observed"/>
      <Metric label="Live connectors" value={conns.filter(x=>x.configured).length} meta={`${conns.length} registered`} tone="pink"/>
    </div>
    <section className="panel"><PanelTitle title="Readiness" sub="Green means the dependency is really present, not assumed"/>
      <div className="readyList">{rows.map(([n,ok,d])=><div className="readyRow" key={n}><span className={`dot ${ok?"green":"pink"}`}/><div><b>{n}</b><small>{d}</small></div><span className={`tag ${ok?"active":"gap"}`}>{ok?"ready":"attention"}</span></div>)}</div>
    </section>
    <section className="panel"><PanelTitle title="Execution backends" sub="Rules compile to each backend's native query"/>
      <div className="readyList">{conns.map(x=><div className="readyRow" key={x.name}><span className={`dot ${x.configured?"green":"pink"}`}/><div><b>{x.label}</b><small>{x.configured?"Executes queries":"Compile-only until configured"}</small></div><span className={`tag ${x.configured?"active":""}`}>{x.mode}</span></div>)}</div>
    </section>
    <SynthesisCard/>
    <section className="panel"><PanelTitle title="Telemetry store" sub="Events the local backend can hunt over" action={role==="Administrator"&&<button className="primary" disabled={busy} onClick={ingest}>{busy?"Loading…":"Load default EVTX samples"}</button>}/>
      {tel?.sources?.length?<div className="readyList">{tel.sources.map(x=><div className="readyRow" key={x.source}><span className="dot green"/><div><b>{x.source}</b><small>{x.kind}</small></div><span className="tag">{x.events} events</span></div>)}</div>:<div className="emptyState">No telemetry loaded yet.</div>}
    </section>
  </>;
}

function Generator({role,notify}) {
  const [plans,setPlans]=useState([]);
  const [selected,setSelected]=useState("");
  const [objective,setObjective]=useState("");
  const [out,setOut]=useState(null);
  const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(true);
  const [query,setQuery]=useState("");
  const [pickerOpen,setPickerOpen]=useState(false);
  const [detailsOpen,setDetailsOpen]=useState(false);
  const [sigmaOpen,setSigmaOpen]=useState(false);
  const [provider,setProvider]=useState("corpus");

  useEffect(()=>{
    let alive=true;

    const loadPlans=async()=>{
      try{
        setLoading(true);

        const pages=await Promise.all([
          api("/detection-plans?page=1&page_size=200"),
          api("/detection-plans?page=2&page_size=200"),
          api("/detection-plans?page=3&page_size=200")
        ]);

        if(!alive)return;

        const rows=pages.flatMap(x=>Array.isArray(x?.items)?x.items:[]);

        setPlans(rows);

        if(rows[0]){
          setSelected(rows[0].technique_id);
          setObjective(rows[0].detection_intent?.objective||"");
        }
      }catch(e){
        if(alive){
          setPlans([]);
          notify("Unable to load Detection Plans.");
        }
      }finally{
        if(alive)setLoading(false);
      }
    };

    loadPlans();

    return()=>{alive=false};
  },[]);

  const current=plans.find(x=>x.technique_id===selected);

  const filteredPlans=plans.filter(plan=>{
    const text=[
      plan.technique_id,
      plan.plan_id,
      plan.detection_intent?.objective,
      ...(plan.detection_intent?.observable_behaviors||[])
    ].join(" ").toLowerCase();

    return text.includes(query.trim().toLowerCase());
  }).slice(0,12);

  const choosePlan=(plan)=>{
    setSelected(plan.technique_id);
    setObjective(plan.detection_intent?.objective||"");
    setOut(null);
    setPickerOpen(false);
    setQuery("");
  };

  const generate=async()=>{
    if(role==="Monitor"||!selected||!objective.trim())return;

    setBusy(true);

    try{
      const result=await api("/generator/generate-rule",{
        method:"POST",
        body:JSON.stringify({
          hypothesis_text:objective.trim(),
          target_technique_id:selected,
          target_platform:"windows",
          provider
        })
      });

      setOut(result);
      notify(result.gate&&result.gate.executable===false?"Rule generated but blocked by the validation gate.":"Detection generation completed.");
    }catch(e){
      setOut(null);
      notify(`Generator request failed: ${e.message}`);
    }finally{
      setBusy(false);
    }
  };

  return <>
    <PageHeader
      eyebrow="DETECTION WORKBENCH"
      title="Rule Generator"
      sub="Turn a grounded hunting objective into a reviewable detection artifact."
    />

    <section className="generator">
      <div className="generatorGrid">

        <div className="generatorSource">
          <div className="generatorSectionLabel">01 · Detection Plan</div>

          <div className="generatorPlanHeader">
            <div>
              <div className="generatorEyebrow">
                {loading ? "Loading grounded plans" : `${plans.length} grounded Detection Plans`}
              </div>

              <h3>
                {current?.technique_id || "Select a Detection Plan"}
              </h3>
            </div>

            {current&&
              <span className="generatorTechniqueBadge">
                ATT&CK
              </span>
            }
          </div>

          <div className="generatorPicker">
            <button
              type="button"
              className="generatorPickerButton"
              onClick={()=>!loading&&setPickerOpen(x=>!x)}
              disabled={loading||!plans.length}
            >
              <span>
                {current
                  ? current.detection_intent?.objective || "Detection objective"
                  : loading
                    ? "Loading Detection Plans…"
                    : "Select a Detection Plan"
                }
              </span>

              <span className="generatorPickerIcon">
                {pickerOpen ? "⌃" : "⌄"}
              </span>
            </button>

            {pickerOpen&&
              <div className="generatorPickerMenu">
                <input
                  autoFocus
                  className="generatorPickerSearch"
                  value={query}
                  onChange={e=>setQuery(e.target.value)}
                  placeholder="Search technique, objective, or behavior…"
                />

                <div className="generatorPickerResults">
                  {filteredPlans.length>0
                    ? filteredPlans.map(plan=>
                        <button
                          type="button"
                          key={plan.plan_id}
                          className={`generatorPickerItem ${
                            plan.technique_id===selected ? "active" : ""
                          }`}
                          onClick={()=>choosePlan(plan)}
                        >
                          <span className="generatorPickerTechnique">
                            {plan.technique_id}
                          </span>

                          <span className="generatorPickerObjective">
                            {plan.detection_intent?.objective || "Detection objective"}
                          </span>

                          <span className="generatorPickerPlan">
                            {plan.plan_id}
                          </span>
                        </button>
                      )
                    : <div className="generatorPickerEmpty">
                        No Detection Plans match your search.
                      </div>
                  }
                </div>
              </div>
            }
          </div>

          {current&&<>
            <div className="generatorPlanMeta">
              <span>{current.plan_id}</span>
              <span>{current.model}</span>
              <span>Grounded</span>
            </div>

            <div className="generatorObjectiveCard">
              <div className="generatorSectionLabel">
                Grounded objective
              </div>

              <p>{objective}</p>

              <button
                type="button"
                className="generatorTextButton"
                onClick={()=>setDetailsOpen(true)}
              >
                View plan details →
              </button>
            </div>
          </>}
        </div>

        <div className="generatorPipeline">
          <div className="generatorSectionLabel">02 · Detection workflow</div>

          <div className="generatorSteps">
            <div className="generatorStep active">
              <span>01</span>
              <div>
                <b>Objective</b>
                <small>Grounded hunting intent</small>
              </div>
            </div>

            <div className="generatorStepLine"/>

            <div className={`generatorStep ${out?"complete":"active"}`}>
              <span>02</span>
              <div>
                <b>Generate</b>
                <small>Create a reviewable rule draft</small>
              </div>
            </div>

            <div className="generatorStepLine"/>

            <div className={`generatorStep ${out?"active":""}`}>
              <span>03</span>
              <div>
                <b>Review</b>
                <small>Inspect the generated Sigma artifact</small>
              </div>
            </div>
          </div>

          <div className="generatorSource">
            <b>Detection source</b>
            <ProviderPicker value={provider} onChange={setProvider} />
          </div>

          <div className="generatorAction">
            <div>
              <b>Generate detection draft</b>
              <small>
                The selected source produces a Sigma rule, then the validation gate checks it.
              </small>
            </div>

            <button
              className="primary"
              disabled={
                role==="Monitor"||
                busy||
                loading||
                !selected||
                !objective.trim()
              }
              onClick={generate}
            >
              {busy?"Generating…":"Generate detection"}
            </button>

            {role==="Monitor"&&
              <div className="generatorPermission">
                Monitor access is read-only. Detection generation requires Analyst access.
              </div>
            }
          </div>
        </div>
      </div>

      {out&&
        <div className="generatorOutput">
          <div className="generatorResultTop">
            <div>
              <div className="generatorSectionLabel">03 · Review</div>
              <h3>Detection draft generated</h3>
              <p>
                A rule artifact is ready for inspection before any validation or activation step.
              </p>
            </div>

            <span className={`generatorResultStatus ${out.status||"draft"}`}>
              {out.status||"draft"}
            </span>
          </div>

          <div className="generatorResultMeta">
            <div>
              <span>Technique</span>
              <b>{selected}</b>
            </div>

            <div>
              <span>Method</span>
              <b>{out.generation_method||"template_v0"}</b>
            </div>

            <div>
              <span>Rule ID</span>
              <b>#{out.id}</b>
            </div>
          </div>

          {out.warning&&
            <div className="generatorWarning">
              <b>Review required</b>
              <span>{out.warning}</span>
            </div>
          }

          <div className="generatorResultActions">
            <button
              type="button"
              className="primary"
              onClick={()=>setSigmaOpen(true)}
            >
              View Sigma rule
            </button>

            <button
              type="button"
              className="secondary"
              onClick={()=>setOut(null)}
            >
              Dismiss result
            </button>
          </div>
        </div>
      }
    </section>

    {detailsOpen&&current&&
      <div
        className="drawerOverlay"
        onClick={()=>setDetailsOpen(false)}
      >
        <aside
          className="drawer generatorDrawer"
          onClick={e=>e.stopPropagation()}
        >
          <div className="drawerHead">
            <div>
              <div className="generatorSectionLabel">Detection Plan</div>
              <h3>{current.technique_id}</h3>
            </div>

            <button
              type="button"
              className="iconButton"
              onClick={()=>setDetailsOpen(false)}
              aria-label="Close"
            >
              ×
            </button>
          </div>

          <div className="drawerBody">
            <div className="detailSection">
              <div className="generatorSectionLabel">Plan identity</div>

              <div className="generatorDetailGrid">
                <div>
                  <span>Plan ID</span>
                  <b>{current.plan_id}</b>
                </div>

                <div>
                  <span>Model</span>
                  <b>{current.model}</b>
                </div>
              </div>
            </div>

            <div className="detailSection">
              <div className="generatorSectionLabel">Observable behaviors</div>

              <div className="generatorDetailList">
                {(current.detection_intent?.observable_behaviors||[]).map((x,i)=>
                  <div key={i}>{x}</div>
                )}
              </div>
            </div>

            {(current.known_limitations||[]).length>0&&
              <div className="detailSection">
                <div className="generatorSectionLabel">Known limitations</div>

                <div className="generatorDetailList muted">
                  {current.known_limitations.map((x,i)=>
                    <div key={i}>{x}</div>
                  )}
                </div>
              </div>
            }
          </div>
        </aside>
      </div>
    }

    {sigmaOpen&&out&&
      <div
        className="drawerOverlay"
        onClick={()=>setSigmaOpen(false)}
      >
        <aside
          className="drawer generatorDrawer generatorSigmaDrawer"
          onClick={e=>e.stopPropagation()}
        >
          <div className="drawerHead">
            <div>
              <div className="generatorSectionLabel">Generated artifact</div>
              <h3>Sigma rule</h3>
            </div>

            <button
              type="button"
              className="iconButton"
              onClick={()=>setSigmaOpen(false)}
              aria-label="Close"
            >
              ×
            </button>
          </div>

          <div className="drawerBody">
            {out.warning&&
              <div className="generatorWarning">
                <b>Review required</b>
                <span>{out.warning}</span>
              </div>
            }

            <pre className="generatorSigmaCode">
              {out.generated_yaml||JSON.stringify(out,null,2)}
            </pre>
          </div>
        </aside>
      </div>
    }
  </>;
}


function Admin({session,notify}) {
  const [users,setUsers]=useState(
    Object.entries(DEMO_USERS).map(
      ([email,u])=>({email,...u,status:"Active",mfa:"Required"})
    )
  );

  const [audit,setAudit]=useState([
    {
      actor:session.name,
      action:"Signed in",
      object:"Workspace",
      time:"Now"
    }
  ]);

  const [controls,setControls]=useState({
    maintenance_mode:false,
    audit_logging:true,
    auto_refresh:true,
    campaign_execution:true,
    detection_generation:true,
    require_detection_validation:true,
    allow_source_changes:true,
    finding_retention_days:180,
    session_timeout_minutes:60
  });

  const [saving,setSaving]=useState(false);

  useEffect(()=>{
    api("/admin-control")
      .then(x=>{
        if(x?.settings){
          setControls(v=>({...v,...x.settings}));
        }

        if(Array.isArray(x?.audit)){
          setAudit(x.audit);
        }
      })
      .catch(()=>{});
  },[]);

  const saveControl=async(key,value)=>{
    if(session.role!=="Administrator")return;

    const next={...controls,[key]:value};

    setControls(next);
    setSaving(true);

    try{
      const r=await api(
        "/admin-control",
        {
          method:"PATCH",
          body:JSON.stringify({
            settings:{[key]:value},
            actor:session.name
          })
        }
      );

      if(Array.isArray(r?.audit)){
        setAudit(r.audit);
      }

      notify("Workspace control updated.");
    }catch(e){
      setControls(controls);
      notify(e.message||"Control could not be saved.");
    }finally{
      setSaving(false);
    }
  };

  const changeRole=(i,role)=>{
    if(session.role!=="Administrator")return;

    const u=users[i];

    if(!window.confirm(
      `Change ${u.email} to ${role}? This is a sensitive access change.`
    ))return;

    setUsers(x=>
      x.map(
        (v,j)=>
          j===i
            ? {
                ...v,
                role,
                permissions:
                  role==="Administrator"
                    ? ["*"]
                    : role==="Analyst"
                      ? ["view","investigate","create","validate"]
                      : ["view"]
              }
            : v
      )
    );

    setAudit(x=>[
      {
        actor:session.name,
        action:`Changed role to ${role}`,
        object:u.email,
        time:new Date().toLocaleString()
      },
      ...x
    ]);

    notify("Role change recorded in the audit view.");
  };

  const resetDemo=async()=>{
    if(!window.confirm(
      "Reset workspace control settings to the safe defaults?"
    ))return;

    const defaults={
      maintenance_mode:false,
      audit_logging:true,
      auto_refresh:true,
      campaign_execution:true,
      detection_generation:true,
      require_detection_validation:true,
      allow_source_changes:true,
      finding_retention_days:180,
      session_timeout_minutes:60
    };

    setControls(defaults);

    try{
      const r=await api(
        "/admin-control",
        {
          method:"PUT",
          body:JSON.stringify({
            settings:defaults,
            actor:session.name
          })
        }
      );

      if(Array.isArray(r?.audit)){
        setAudit(r.audit);
      }

      notify("Workspace controls restored to defaults.");
    }catch(e){
      notify("Defaults could not be restored.");
    }
  };

  const Control=({title,sub,field})=>
    <div className="controlRow">
      <div>
        <b>{title}</b>
        <small>{sub}</small>
      </div>

      <button
        className={`controlToggle ${controls[field]?"enabled":""}`}
        onClick={()=>saveControl(field,!controls[field])}
        disabled={saving}
      >
        <i/>
        {controls[field]?"ON":"OFF"}
      </button>
    </div>;

  return <>
    <PageHeader
      eyebrow="CONTROL PLANE"
      title="Administration"
      sub="Govern identity, workspace behavior, data operations and security policies from one administrator control plane."
    />

    <div className="adminBanner">
      <b>Administrator privileges</b>
      <span>
        Full platform access · sensitive changes require confirmation · privileged actions are auditable.
      </span>
    </div>

    <section className="panel">
      <PanelTitle
        title="Identity & role control"
        sub="Exactly three workspace roles: Administrator, Analyst, Monitor."
      />

      <div className="userTable">
        {users.map((u,i)=>
          <div className="userRow" key={u.email}>
            <div className="avatar">{initials(u.name)}</div>

            <div>
              <b>{u.name}</b>
              <small>{u.email}</small>
            </div>

            <select
              value={u.role}
              onChange={e=>changeRole(i,e.target.value)}
            >
              <option>Administrator</option>
              <option>Analyst</option>
              <option>Monitor</option>
            </select>

            <span>{u.mfa}</span>
            <span>{u.status}</span>
          </div>
        )}
      </div>
    </section>

    <section className="adminControlGrid">

      <section className="panel">
        <PanelTitle
          title="Workspace controls"
          sub="Operational switches that change how the platform behaves."
        />

        <div className="controlList">

          <Control
            field="auto_refresh"
            title="Automatic data refresh"
            sub="Allow live workspace views to refresh backend data automatically."
          />

          <Control
            field="campaign_execution"
            title="Campaign execution"
            sub="Allow Analyst and Administrator roles to start campaign runs."
          />

          <Control
            field="detection_generation"
            title="Detection generation"
            sub="Allow the Rule Generator workflow to create detection artifacts."
          />

          <Control
            field="allow_source_changes"
            title="Source management"
            sub="Allow administrators and analysts to add or modify workspace sources."
          />

        </div>
      </section>

      <section className="panel">
        <PanelTitle
          title="Security & governance"
          sub="Guardrails for privileged and security-sensitive operations."
        />

        <div className="controlList">

          <Control
            field="audit_logging"
            title="Privileged audit logging"
            sub="Record administrator actions and workspace control changes."
          />

          <Control
            field="require_detection_validation"
            title="Require detection validation"
            sub="Keep generated detections in review until validation is completed."
          />

          <Control
            field="maintenance_mode"
            title="Maintenance mode"
            sub="Place the workspace into controlled maintenance state."
          />

        </div>
      </section>

    </section>

    <section className="panel">
      <PanelTitle
        title="Data governance"
        sub="Retention and session policies for the operational workspace."
      />

      <div className="governanceGrid">

        <label>
          <span>Finding retention</span>

          <select
            value={controls.finding_retention_days}
            onChange={e=>
              saveControl(
                "finding_retention_days",
                Number(e.target.value)
              )
            }
          >
            <option value="30">30 days</option>
            <option value="90">90 days</option>
            <option value="180">180 days</option>
            <option value="365">365 days</option>
            <option value="730">730 days</option>
          </select>

          <small>
            Defines the workspace retention policy for finding records.
          </small>
        </label>

        <label>
          <span>Session timeout</span>

          <select
            value={controls.session_timeout_minutes}
            onChange={e=>
              saveControl(
                "session_timeout_minutes",
                Number(e.target.value)
              )
            }
          >
            <option value="15">15 minutes</option>
            <option value="30">30 minutes</option>
            <option value="60">60 minutes</option>
            <option value="120">120 minutes</option>
            <option value="480">8 hours</option>
          </select>

          <small>
            Workspace policy for authenticated session lifetime.
          </small>
        </label>

        <div className="governanceState">
          <small>Current posture</small>
          <b>
            {controls.maintenance_mode
              ? "Maintenance"
              : "Operational"}
          </b>

          <span>
            Audit logging{" "}
            {controls.audit_logging?"enabled":"disabled"}
          </span>
        </div>

      </div>
    </section>

    <section className="panel">
      <PanelTitle
        title="Permission model"
        sub="Access follows identity → role → permissions."
      />

      <div className="permissionMatrix">
        {[
          ["Campaigns","View","Create / Edit / Run","Create / Edit / Run"],
          ["Findings","View","Investigate / Validate","Investigate / Validate"],
          ["Detections","View","Generate / Validate","Generate / Validate"],
          ["ATT&CK / Hypotheses","View","Investigate","Investigate"],
          ["Data / Pipeline","View","Operate","Operate"],
          ["Administration","—","—","Full control"]
        ].map((r,i)=>
          <div key={i} className="permRow">
            {r.map((x,j)=>
              <span
                key={j}
                className={j===0?"permName":""}
              >
                {x}
              </span>
            )}
          </div>
        )}
      </div>
    </section>

    <section className="panel">
      <PanelTitle
        title="Administrator actions"
        sub="Safe workspace-level maintenance actions."
      />

      <div className="adminActionGrid">

        <button
          className="adminAction"
          onClick={()=>{
            api("/health")
              .then(r=>notify(
                `Platform health: ${r.status||"ok"}`
              ))
              .catch(()=>notify("Health check failed."));
          }}
        >
          <b>Run health check</b>
          <small>Verify that the application service is responding.</small>
        </button>

        <button
          className="adminAction"
          onClick={()=>{
            setAudit(x=>[
              {
                actor:session.name,
                action:"Viewed workspace governance",
                object:"Administration",
                time:new Date().toLocaleString()
              },
              ...x
            ]);

            notify("Governance view refreshed.");
          }}
        >
          <b>Review governance</b>
          <small>Refresh the local privileged activity trail.</small>
        </button>

        <button
          className="adminAction dangerAction"
          onClick={resetDemo}
        >
          <b>Restore safe defaults</b>
          <small>Reset workspace controls after explicit confirmation.</small>
        </button>

      </div>
    </section>

    <section className="panel">
      <PanelTitle
        title="Audit log"
        sub="Recent privileged actions and workspace control changes."
      />

      {audit.map((a,i)=>
        <div className="auditRow" key={i}>
          <b>{a.action}</b>
          <span>{a.actor} · {a.object}</span>
          <time>{a.time}</time>
        </div>
      )}
    </section>
  </>;
}

function ObjectDrawer({detail,close,role,notify,go,open}) {
  if(!detail)return null;const d=detail.data||{};
  const campaignTechnique =
    detail.type==="campaign"
      ? (d.technique_id||d.technique||d.hypotheses?.[0]?.technique_id||null)
      : null;
  const title=detail.type==="campaign"?d.name:detail.type==="finding"?d.rule_title:detail.type==="rule"?d.title:detail.type==="technique"?d.name:detail.type==="hypothesis"?(d.title||d.hypothesis_text):"Investigation";
  return <div className="drawerOverlay" onMouseDown={e=>e.target===e.currentTarget&&close()}><aside className="drawer"><div className="drawerHead"><div><small>{detail.type.toUpperCase()} INVESTIGATION</small><h2>{title||"Object detail"}</h2></div><button onClick={close}>×</button></div><div className="drawerBody">
    <div className="objectStats"><div><small>Risk / confidence</small><b>{d.risk_score!=null?d.risk_score:d.confidence!=null?pct(d.confidence):"—"}</b></div><div><small>Status</small><b>{safe(d.status||d.verification_status||d.validation_status)}</b></div><div><small>ATT&CK</small><b>{campaignTechnique||(d.attack_technique_ids||d.technique_ids||[d.technique_id]).filter(Boolean).join(" · ")||"Linked to campaign hypotheses"}</b></div><div><small>Source</small><b>{safe(d.source_dataset||d.target_platform||d.route)}</b></div></div>
    <Lineage type={detail.type} d={d}/>
    {detail.type==="finding"&&<FindingEvidence f={d} role={role} notify={notify} open={open}/>}
    {detail.type==="campaign"&&<CampaignObject d={d} role={role} notify={notify} openObj={open}/>}
    {detail.type==="hypothesis"&&<div className="detailSection"><h3>Reasoning</h3><p>{d.reasoning||d.hypothesis_text||"Grounded hypothesis generated from behavioral evidence."}</p><h3>Required telemetry</h3><p>{d.required_telemetry||"Telemetry requirements are attached to the hypothesis record."}</p></div>}
    {detail.type==="technique"&&<div className="detailSection"><h3>Coverage relationship</h3><p>This technique connects ATT&CK knowledge to detection rules, campaign hypotheses and observed findings.</p><div className="coverageBox"><b>{d.rule_count||0}</b><span>rules linked</span></div></div>}
    {detail.type==="rule"&&<div className="detailSection"><h3>Detection description</h3><p>{d.description||"Reviewable Sigma detection artifact."}</p><h3>Lifecycle</h3><Flow items={["Draft","Validated","Approved","Active"]}/></div>}
  </div></aside></div>;
}

function Lineage({type,d}) { const items=type==="finding"?["ATT&CK","Hypothesis","Campaign","Detection","Finding"]:type==="campaign"?["Hypothesis","Detection","Hunt","Finding"]:type==="hypothesis"?["Telemetry","Signal","Hypothesis","Detection Plan"]:["ATT&CK","Detection","Finding"];return <div className="detailSection"><h3>Object lineage</h3><Flow items={items}/></div>; }
function FindingEvidence({f:f0,role,notify,open}) {
  const [f,setF]=useState(f0);
  const [note,setNote]=useState("");
  const [saving,setSaving]=useState(false);
  useEffect(()=>setF(f0),[f0]);
  const canDecide=role==="Analyst"||role==="Administrator";
  const decide=async verdict=>{
    setSaving(true);
    try{
      await api(`/findings/${encodeURIComponent(f.finding_id)}/verdict`,{method:"POST",body:JSON.stringify({verdict,note})});
      setF(await api(`/findings/${encodeURIComponent(f.finding_id)}`));
      setNote("");notify?.("Verdict saved and recorded as a training label.");
    }catch(e){notify?.(e.message)}finally{setSaving(false)}
  };
  const tri=f.triage||{};
  const isML=tri.triage_source==="ml_model";
  const contribs=isML?[]:Object.entries(tri.contributions||{}).filter(([,v])=>v).sort((a,b)=>Math.abs(b[1])-Math.abs(a[1]));
  const refs=Array.isArray(f.event_references)
    ? f.event_references
    : (f.event_references
      ? (()=>{try{return JSON.parse(f.event_references)}catch{return [f.event_references]}})()
      : []);

  const hosts=Array.isArray(f.hosts)?f.hosts:(f.hosts?[f.hosts]:[]);
  const users=Array.isArray(f.users)?f.users:(f.users?[f.users]:[]);
  const processes=Array.isArray(f.processes)
    ? f.processes
    : (f.processes
      ? (()=>{try{
          const x=JSON.parse(f.processes);
          return Array.isArray(x)?x:[x];
        }catch{return [f.processes]}})()
      : []);

  const start=f.time_start||"—";
  const end=f.time_end||start;

  const procLabel=p=>typeof p==="string"?p:[p.parent_image&&`${p.parent_image.split("\\").pop()} →`,(p.command_line||p.image||"")].filter(Boolean).join(" ");
  const refLabel=r=>typeof r==="string"?r:[r.connector,r.source,r.event_id&&`event ${r.event_id}`].filter(Boolean).join(" · ");
  const events=[
    [start,"Detection triggered",f.rule_title||"Detection rule","Rule matched available telemetry"],
    [start,"Telemetry correlated",refs.length?refs.map(refLabel).join("; "):"No event reference","Evidence linked to finding"],
    [end,"Context observed",hosts.length?hosts.join(", "):"No host recorded","Telemetry context"],
    ["Current","Analyst decision",f.verification_status||"unverified","Current investigation state"]
  ];

  return <div className="detailSection">
    <h3>Evidence timeline</h3>
    <div className="evidence">
      {events.map((e,i)=>
        <div className="evidenceRow" key={i}>
          <i/>
          <time>{e[0]}</time>
          <div>
            <b>{e[1]}</b>
            <strong>{e[2]}</strong>
            <span>{e[3]}</span>
          </div>
          <em>{i===3?"STATE":"EVENT"}</em>
        </div>
      )}
    </div>

    <div className="contextGrid">
      <div><small>Host</small><b>{hosts.join(", ")||"—"}</b></div>
      <div><small>User</small><b>{users.join(", ")||"—"}</b></div>
      <div><small>Process</small><b>{processes.length?processes.map(procLabel).join(" | ").slice(0,300):"—"}</b></div>
      <div><small>Probability</small><b>{f.threat_probability==null?"Not available":pct(f.threat_probability)}</b></div>
    </div>
    {isML&&tri.ml&&<div className="triageBox"><h3>ML triage <span className="tag">analyst-assisted</span></h3>
      <p>Model {tri.ml.model_version} · predicted class <b>{String(tri.ml.predicted_class||"").replace(/_/g," ")}</b> · route <b>{String(tri.ml.route||"").replace(/_/g," ")}</b>. Prioritisation only, not a verdict.</p>
      {[["True positive",tri.ml.probability_true_positive],["Benign positive",tri.ml.probability_benign_positive],["False positive",tri.ml.probability_false_positive]].map(([k,v])=><div className="factorRow" key={k}><span>{k}</span><div className="factorBar"><i style={{width:`${Math.round((v||0)*100)}%`,background:k==="True positive"?"var(--pink2)":"var(--green2)"}}/></div><b>{Math.round((v||0)*100)}%</b></div>)}
    </div>}
    {!isML&&tri.ml&&tri.ml.available===false&&<p style={{opacity:.75,fontSize:12}}>Triage source: heuristic fallback (ML unavailable: {tri.ml.reason}).</p>}
    {contribs.length>0&&<div className="triageBox"><h3>Why this score</h3>
      <p>Route: <b>{String(tri.route||"").replace(/_/g," ")}</b> · model {tri.model}. Positive values raise risk, negative values lower it.</p>
      {contribs.map(([k,v])=><div className="factorRow" key={k}><span>{k.replace(/_/g," ")}</span><div className="factorBar"><i style={{width:`${Math.min(100,Math.abs(v)*45)}%`,background:v>=0?"var(--pink2)":"var(--green2)"}}/></div><b>{v>0?"+":""}{v}</b></div>)}
      {tri.analyst_prior?<p>Analyst history for this rule shifted the score by <b>{tri.analyst_prior>0?"+":""}{tri.analyst_prior}</b>.</p>:null}
    </div>}
    {f.compiled_query&&<details className="qBox"><summary>Compiled query</summary><pre>{f.compiled_query}</pre></details>}
    <div className="verdictBox"><h3>Analyst decision</h3>
      <p>Current: <span className="tag">{f.analyst_verdict||f.verification_status||"unverified"}</span></p>
      {canDecide?<>
        <textarea placeholder="Optional note for the audit trail" value={note} onChange={e=>setNote(e.target.value)}/>
        <div className="headerActions">
          <button className="primary" disabled={saving} onClick={()=>decide("true_positive")}>True positive</button>
          <button className="ghost" disabled={saving} onClick={()=>decide("false_positive")}>False positive</button>
          <button className="ghost" disabled={saving} onClick={()=>decide("benign_expected")}>Benign / expected</button>
        </div></>:<p className="muted">Your role can view findings but not decide them.</p>}
      {(f.verdicts||[]).length>0&&<div className="verdictHist">{f.verdicts.map((v,i)=><div key={i}><b>{v.verdict.replace(/_/g," ")}</b> · {v.analyst} · {(v.at||"").slice(0,16).replace("T"," ")}{v.note?` · ${v.note}`:""}</div>)}</div>}
    </div>
  </div>;
}
const STAGE_TONE={done:"ok",running:"run",failed:"bad",pending:"idle",idle:"idle",not_configured:"idle"};
function authHeaders(){try{const s=JSON.parse(localStorage.getItem("threathunt_session")||"null");return s?.token?{Authorization:`Bearer ${s.token}`}:{}}catch{return {}}}

async function downloadReport(id){
  const res=await fetch(`${API}/campaigns/${id}/report`,{headers:authHeaders()});
  if(!res.ok)throw new Error(`Report failed (HTTP ${res.status})`);
  const url=URL.createObjectURL(await res.blob());
  const a=document.createElement("a");a.href=url;a.download=`hunt-report-${id}.md`;a.click();URL.revokeObjectURL(url);
}

function AttackGraph({graph,open}) {
  const cols=["host","process","finding","technique"];
  const nodes=(graph?.nodes||[]);
  if(!nodes.length)return <div className="emptyState">No findings yet, so there is nothing to graph. Run the campaign to build the attack graph.</div>;
  const top=nodes.filter(n=>n.kind==="finding").sort((a,b)=>(b.risk||0)-(a.risk||0)).slice(0,10).map(n=>n.id);
  const keepEdges=graph.edges.filter(e=>top.includes(e.to)||top.includes(e.from));
  const keepIds=new Set(keepEdges.flatMap(e=>[e.from,e.to]));
  const vis=nodes.filter(n=>keepIds.has(n.id));
  const W=920,rowH=34,pos={};
  const byCol=cols.map(k=>vis.filter(n=>n.kind===k));
  byCol.forEach((list,ci)=>list.forEach((n,i)=>{pos[n.id]={x:70+ci*(W-140)/3,y:24+i*rowH}}));
  const H=Math.max(...byCol.map(l=>l.length),1)*rowH+30;
  const tone=n=>n.kind==="finding"?((n.risk||0)>=80?"var(--pink2)":(n.risk||0)>=55?"var(--blue2)":"var(--green2)"):"var(--muted)";
  return <div className="graphWrap"><svg viewBox={`0 0 ${W} ${H}`} width="100%">
    {keepEdges.map((e,i)=>pos[e.from]&&pos[e.to]&&<path key={i} d={`M${pos[e.from].x+50},${pos[e.from].y} C${pos[e.from].x+110},${pos[e.from].y} ${pos[e.to].x-110},${pos[e.to].y} ${pos[e.to].x-50},${pos[e.to].y}`} fill="none" stroke="var(--border)" strokeWidth="1.2"/>)}
    {vis.map(n=><g key={n.id} transform={`translate(${pos[n.id].x},${pos[n.id].y})`} style={{cursor:n.kind==="finding"?"pointer":"default"}} onClick={()=>n.kind==="finding"&&open?.({type:"finding",data:{finding_id:n.id}})}>
      <rect x="-50" y="-11" width="100" height="22" rx="7" fill="var(--surface2)" stroke={tone(n)}/>
      <text textAnchor="middle" y="4" fontSize="8.5" fill="var(--text)">{String(n.label).slice(0,17)}</text>
    </g>)}
    {cols.map((c,i)=><text key={c} x={70+i*(W-140)/3} y={H-4} textAnchor="middle" fontSize="8" fill="var(--muted)">{c.toUpperCase()}</text>)}
  </svg><small className="muted">Top 10 findings by risk. Click a finding to open it.</small></div>;
}


function WorkflowMap({pipe,onConn}) {
  const st=Object.fromEntries((pipe?.stages||[]).map(x=>[x.id,x]));
  const conns=pipe?.connectors||[];
  const n=Math.max(conns.length,1),RH=58,top=34,H=top+Math.max(n*RH,130)+10,mid=top+(H-top-10)/2,W=1000,w=142,h=52;
  const X=[0,168,336,520,694,858];
  const cols=[["hypotheses","GENERATE"],["detection","DETECT"],["translate","TRANSLATE"],["execute","EXECUTE"],["score","SCORE"],["review","REVIEW"]];
  const tone=s=>STAGE_TONE[s]||"idle";
  const cut=(t,m)=>{t=String(t||"");return t.length>m?t.slice(0,m-1)+"…":t};
  const edge=(x1,y1,x2,y2,t,k)=>{const m=(x1+x2)/2;return <path key={k} className={`wmEdge ${t}`} d={`M${x1} ${y1} C${m} ${y1} ${m} ${y2} ${x2} ${y2}`}/>};
  const node=(x,y,ww,t,l,sub,k,click)=><g key={k} className={`wmNode ${t}`} transform={`translate(${x},${y})`} onClick={click} style={click?{cursor:"pointer"}:null}>
    <rect width={ww} height={h} rx="14"/><circle cx="14" cy="16" r="4"/>
    <text x="26" y="20" className="wmT">{cut(l,Math.floor(ww/7))}</text><text x="14" y="39" className="wmS">{cut(sub,Math.floor(ww/5.2))}</text></g>;
  const yOf=i=>top+i*RH+(RH-h)/2;
  const main=cols.filter(c=>c[0]!=="execute");
  const stOf=id=>st[id]||{status:"pending",summary:"",count:0};
  const els=[];
  const exSt=tone(stOf("execute").status);
  main.forEach(([id],i)=>{const idx=cols.findIndex(c=>c[0]===id);if(idx>0&&id!=="score"){const prev=cols[idx-1][0];if(prev!=="execute")els.push(edge(X[idx-1]+w,mid,X[idx],mid,tone(stOf(prev).status),"e"+id))}});
  conns.forEach((c,i)=>{const y=yOf(i)+h/2,t=tone(c.status);
    els.push(edge(X[2]+w,mid,X[3],y,tone(stOf("translate").status),"a"+i));
    els.push(edge(X[3]+150,y,X[4],mid,t,"b"+i))});
  if(!conns.length)els.push(edge(X[2]+w,mid,X[4],mid,"idle","e0"));
  return <div className="wmWrap"><svg viewBox={`0 0 ${W} ${H}`} className="wm">
    {cols.map(([,l],i)=><text key={l} x={X[i]+(i===3?75:w/2)} y="16" textAnchor="middle" className="wmCol">{l}</text>)}
    {els}
    {main.map(([id,l])=>{const idx=cols.findIndex(c=>c[0]===id),s=stOf(id);return node(X[idx],mid-h/2,w,tone(s.status),`${s.count??0} · ${s.label||l}`,s.summary,id)})}
    {conns.map((c,i)=>node(X[3],yOf(i),150,tone(c.status),c.label||c.name,c.mode==="live"?(c.executions?`${c.hits} hit(s) · ${c.scanned||0} scanned`:"ready"):"not configured","c"+i,onConn))}
  </svg><div className="wmLegend"><span className="ok">completed</span><span className="run">running</span><span className="bad">failed</span><span className="idle">pending / not configured</span></div></div>;
}

function CampaignLive({campaignId,status,role,notify,open,onFinished,tab,setTab,counts={},findings=[],campaign=null}) {
  const [pipe,setPipe]=useState(null);
  const [execs,setExecs]=useState([]);
  const [events,setEvents]=useState([]);
  const [graph,setGraph]=useState(null);
  const [sel,setSel]=useState(null);
  const running=["running","hunting","generating_rules"].includes(status);
  const load=useCallback(async()=>{
    try{
      const [p,x,e]=await Promise.all([api(`/campaigns/${campaignId}/pipeline`),api(`/campaigns/${campaignId}/executions`),api(`/campaigns/${campaignId}/events`)]);
      setPipe(p);setExecs(x.items||[]);setEvents(e.items||[]);
    }catch(err){notify?.(err.message)}
  },[campaignId]);
  useEffect(()=>{load()},[load,status]);
  useEffect(()=>{if(!running)return;const t=setInterval(async()=>{await load();try{const c=await api(`/campaigns/${campaignId}`);if(!["running","hunting","generating_rules"].includes(c.status)){onFinished?.(c)}}catch{}},2000);return()=>clearInterval(t)},[running,load,campaignId]);
  useEffect(()=>{if(tab==="graph")api(`/campaigns/${campaignId}/graph`).then(setGraph).catch(()=>setGraph({nodes:[],edges:[]}))},[tab,campaignId,status]);
  const stages=pipe?.stages||[];
  const conns=pipe?.connectors||[];
  return <div className="campaignSubsection liveBox">
    <div className="sectionTitleRow"><div><h3>Hunt pipeline</h3><small>{running?"Running now, updating live.":"Every stage below reflects what actually executed."}</small></div>
      <div className="headerActions"><button className="ghost" onClick={load}>Refresh</button><button className="ghost" onClick={()=>downloadReport(campaignId).catch(e=>notify?.(e.message))}>Export report (.md)</button></div></div>
    <WorkflowMap pipe={pipe} onConn={()=>setTab("executions")}/>
    {pipe&&pipe.telemetry_events===0&&<div className="emptyState">The local telemetry store is empty. An admin can load EVTX samples under Data Sources, otherwise the first run will try the default public samples.</div>}
    <div className="campTabs">{[["hypotheses",`Hypotheses (${counts.hypotheses||0})`],["rules",`Sigma rules (${counts.rules||0})`],["queries",`Queries (${execs.filter(e=>e.query).length})`],["executions",`Executions (${execs.length})`],["runtime",`Runtime validation (${campaign?.runtime_evidence?.rules?.length||0})`],["findings",`Findings (${counts.findings||0})`],["graph","Attack graph"],["timeline",`Timeline (${events.length})`],["report","Report"]].map(([k,l])=><button key={k} className={tab===k?"active":""} onClick={()=>setTab(k)}>{l}</button>)}</div>
    {tab==="queries"&&(execs.filter(e=>e.query).length?<div className="queryList">{execs.filter(e=>e.query).map(e=><div className="queryCard" key={e.id}><div><b>{e.rule_title||"—"}</b><span className="tag">{e.technique_id}</span><span className="tag">{e.connector}</span></div><pre>{e.query}</pre></div>)}</div>:<div className="emptyState">No queries compiled yet. Run the campaign to translate validated rules.</div>)}
    {tab==="runtime"&&(
      <div className="runtimeEvidencePanel">
        <div className="sectionTitleRow">
          <div>
            <h3>Runtime validation</h3>
            <small>
              Read-only validation data from the detection pipeline. It does not create findings.
            </small>
          </div>
          <span className="tag">Read-only</span>
        </div>

        {campaign?.runtime_evidence?.rules?.length ? (
          <>
            <div className="runtimeEvidenceNotice">
              <b>Important:</b>
              <span>
                A zero-match result is <strong>inconclusive</strong> when runtime visibility is incomplete.
                It must not be interpreted as proof that no attack occurred.
              </span>
            </div>

            <div className="runtimeEvidenceList">
              {campaign.runtime_evidence.rules.map((r,i)=>(
                <div className="runtimeEvidenceCard" key={r.source_rule_id||i}>
                  <div className="runtimeEvidenceHeader">
                    <div>
                      <code>{r.technique_id||"—"}</code>
                      <b>{r.technique_name||"Unknown technique"}</b>
                      <small>
                        {r.analytic_id ? `${r.analytic_id} · ` : ""}
                        {r.source_rule_id}
                      </small>
                    </div>
                    <span className="tag gap">
                      {r.execution_status||"UNKNOWN"}
                    </span>
                  </div>

                  <div className="runtimeEvidenceGrid">
                    <div>
                      <small>Runtime candidate</small>
                      <b>{r.runtime_execution_candidate?"Yes":"No"}</b>
                    </div>
                    <div>
                      <small>Queue</small>
                      <b>{r.queue_present?"Present":"Not present"}</b>
                    </div>
                    <div>
                      <small>Result</small>
                      <b>{r.result_present?"Present":"Not present"}</b>
                    </div>
                    <div>
                      <small>Matches</small>
                      <b>{r.match_count??0}</b>
                    </div>
                  </div>

                  <div className="runtimeEvidenceInterpretation">
                    <small>Interpretation</small>
                    <b>{r.zero_result_interpretation||"—"}</b>
                  </div>

                  {r.disposition&&(
                    <div className="runtimeEvidenceDisposition">
                      <small>Disposition</small>
                      <span>{r.disposition}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        ) : (
          <div className="emptyState">
            No runtime validation data is available for this campaign.
          </div>
        )}
      </div>
    )}

    {tab==="findings"&&(findings.length?<div className="execTable"><div className="execHead"><span>Finding</span><span>Match</span><span>Confidence</span><span/><span/><span/></div>{findings.map(f=><div className="execRow" key={f.id}><span><b>{f.finding_id}</b></span><span>{f.match_type}</span><span>{Math.round((f.confidence||0)*100)}%</span><span/><span/><span/></div>)}</div>:<div className="emptyState">No findings linked to this campaign yet.</div>)}
    {tab==="report"&&<div className="emptyState">Export the full hunt report (hypotheses, rules, queries, findings and analyst decisions).<br/><button className="primary" style={{marginTop:12}} onClick={()=>downloadReport(campaignId).catch(e=>notify?.(e.message))}>Export report (.md)</button></div>}
    {tab==="executions"&&(execs.length?<div className="execTable">
      <div className="execHead"><span>Rule</span><span>Technique</span><span>Backend</span><span>Status</span><span>Scanned</span><span>Hits</span></div>
      {execs.map(e=><React.Fragment key={e.id}><button className="execRow" onClick={()=>setSel(sel===e.id?null:e.id)}>
        <span><b>{e.rule_title||"—"}</b><small>{e.rule_source}{e.source_rule_id?` · ${e.source_rule_id.slice(0,8)}`:""}</small></span>
        <span>{e.technique_id}</span><span>{e.connector}</span><span className={`tag ${e.status==="completed"?"active":e.status==="failed"||e.status==="blocked"?"gap":""}`}>{e.status}</span><span>{e.events_scanned}</span><span><b>{e.hits}</b></span></button>
        {sel===e.id&&<div className="execDetail">
          {e.reason&&<p><b>Note:</b> {e.reason}</p>}
          {(e.validation?.issues||[]).length>0&&<ul>{e.validation.issues.map((i,k)=><li key={k}><span className={`tag ${i.severity==="error"?"gap":""}`}>{i.severity}</span> {i.message}</li>)}</ul>}
          {e.query?<><small>Compiled query ({e.connector})</small><pre>{e.query}</pre></>:<p className="muted">No query was compiled.</p>}
        </div>}</React.Fragment>)}
    </div>:<div className="emptyState">No executions yet. Run the campaign to translate rules and execute them.</div>)}
    {tab==="graph"&&<AttackGraph graph={graph} open={open}/>}
    {tab==="timeline"&&(events.length?<div className="tlList">{events.map(e=><div key={e.id} className={`tlRow ${e.level}`}><time>{(e.at||"").slice(11,19)}</time><span className="tag">{e.stage}</span><p>{e.message}</p></div>)}</div>:<div className="emptyState">No events yet.</div>)}
  </div>;
}

function CampaignObject({d,role,notify,openObj}) {
  const [campaign,setCampaign]=useState(d||null);
  const [selectedRule,setSelectedRule]=useState(null);
  const [audit,setAudit]=useState(null);
  const [loading,setLoading]=useState(true);
  const [auditLoading,setAuditLoading]=useState(false);
  const [busy,setBusy]=useState(false);
  const [tab,setTab]=useState("hypotheses");

  useEffect(()=>{
    if(!d?.id)return;
    let alive=true;
    setLoading(true);

    api(`/campaigns/${d.id}`)
      .then(x=>{if(alive)setCampaign(x)})
      .catch(()=>{if(alive)setCampaign(d)})
      .finally(()=>{if(alive)setLoading(false)});

  return ()=>{alive=false};
  },[d?.id]);

    const transitionRule=async(rule,nextStatus)=>{
    if(role==="Monitor"||!campaign?.id||!rule?.id)return;

    const reasons={
      validated:"Initial analyst validation review.",
      approved:"Approved for campaign execution.",
      active:"Activated for hunt execution."
    };

    try{
      setBusy(true);

      await api(`/campaigns/${campaign.id}/rules/${rule.id}/lifecycle`,{
        method:"POST",
        body:JSON.stringify({
          new_status:nextStatus,
          updated_by:role,
          reason:reasons[nextStatus]||"Lifecycle transition."
        })
      });

      const refreshed=await api(`/campaigns/${campaign.id}`);
      setCampaign(refreshed);

      const updatedRule=(refreshed.rules||[]).find(x=>x.id===rule.id);

      if(updatedRule){
        setSelectedRule(updatedRule);
        openAudit(updatedRule);
      }

      notify?.(`Rule ${nextStatus}.`);
    }catch(e){
      notify?.(e?.message||`Could not move rule to ${nextStatus}.`);
    }finally{
      setBusy(false);
    }
  };

  const run=async()=>{
    if(role==="Monitor"||!campaign?.id)return;

    setBusy(true);
    try{
      const r=await api(`/campaigns/${campaign.id}/run?background=true`,{
        method:"POST",
        body:JSON.stringify({
        technique_ids:(campaign.hypotheses||[])
          .map(h=>h.technique_id)
          .filter(Boolean)
      })
      });

      notify(`Campaign run started: ${r.status||"running"}`);
      setCampaign(await api(`/campaigns/${campaign.id}`));
    }catch(e){
      notify(e?.message || "Campaign run could not be started.");
    }finally{
      setBusy(false);
    }
  };

  const openAudit=async(rule)=>{
    if(!campaign?.id||!rule?.id)return;

    setSelectedRule(rule);
    setAudit(null);
    setAuditLoading(true);

    try{
      const result=await api(
        `/campaigns/${campaign.id}/rules/${rule.id}/audit`
      );
      setAudit(result);
    }catch(e){
      setAudit({
        count:0,
        history:[],
        current_status:rule.validation_status||rule.status||"draft"
      });
    }finally{
      setAuditLoading(false);
    }
  };

  const allRules=campaign?.rules||[];
  const rules=allRules.filter(r=>r.generation_method!=="audit_test" && r.rule_id!=="audit-test-rule-campaign-4");
  const hypotheses=campaign?.hypotheses||[];

  return <div className="detailSection">
    <h3>Campaign operation</h3>

    <p>
      {campaign?.description||"Campaign investigation workflow."}
    </p>

    <div className="campaignDetailStats">
      <b>{campaign?.total_hypotheses||hypotheses.length||0}<span>Hypotheses</span></b>
      <b>{campaign?.total_rules||rules.length||0}<span>Rules</span></b>
      <b>{campaign?.total_findings||0}<span>Findings</span></b>
      <b>{campaign?.risk_score??0}<span>Risk score</span></b>
    </div>

    {role!=="Monitor"&&(
      <button
        className="primary"
        disabled={busy||campaign?.status==="running"}
        onClick={run}
      >
        {busy?"Starting…":campaign?.status==="running"?"Running":"Run campaign →"}
      </button>
    )}

    {campaign?.id&&<CampaignLive campaignId={campaign.id} status={campaign.status} role={role} notify={notify} open={openObj} onFinished={c=>setCampaign(c)} tab={tab} setTab={setTab} counts={{hypotheses:hypotheses.length,rules:rules.length,findings:(campaign.findings||[]).length}} findings={campaign.findings||[]} campaign={campaign}/>}

    {tab==="hypotheses"&&(    <div className="campaignSubsection">
      <div className="sectionTitleRow">
        <div>
          <h3>Campaign hypotheses</h3>
          <small>Grounded inputs selected for this investigation.</small>
        </div>
        <span className="tag">{hypotheses.length} linked</span>
      </div>

      {loading ? (
        <div className="emptyState">Loading campaign data…</div>
      ) : hypotheses.length ? (
        <div className="campaignHypotheses">
          {hypotheses.map(h=>(
            <div className="campaignHypothesis" key={h.id}>
              <div>
                <code>{h.technique_id}</code>
                <b>{h.technique_name}</b>
                <span>{h.hypothesis_text}</span>
              </div>

              <div className="hypothesisMeta">
                <span className="tag">{h.route}</span>
                <span className="tag">
                  {h.detection_plan_id?"Detection Plan linked":"No plan"}
                </span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="emptyState">No hypotheses linked to this campaign.</div>
      )}
    </div>)}
    {tab==="rules"&&(    <div className="campaignSubsection">
      <div className="sectionTitleRow">
        <div>
          <h3>Campaign rules</h3>
          <small>
            Rule lifecycle is tracked separately from the generic Sigma catalog.
          </small>
        </div>
        <span className="tag">{rules.length} linked</span>
      </div>

      {rules.length ? (
        <div className="campaignRules">
          {rules.map(rule=>(
            <button
              className={`campaignRule ${selectedRule?.id===rule.id?"selected":""}`}
              key={rule.id}
              onClick={()=>openAudit(rule)}
            >
              <div className="campaignRuleMain">
                <code>#{rule.id}</code>
                <div>
                  <b>{rule.title||rule.rule_id}</b>
                  <small>
                    {rule.rule_id} · {rule.generation_method||"unknown generation"}
                  </small>
                </div>
              </div>

              <span className={`tag ${rule.validation_status||rule.status}`}>
                {rule.validation_status||rule.status||"draft"}
              </span>

              <span className="campaignRuleArrow">→</span>
            </button>
          ))}
        </div>
      ) : (
        <div className="emptyState">
          No campaign rules have been generated.
        </div>
      )}
    </div>)}
    {tab==="rules"&&selectedRule&&(
      <div className="campaignSubsection auditPanel">
        <div className="sectionTitleRow">
          <div>
            <h3>Lifecycle audit</h3>
            <small>
              Review the rule's validation history when needed.
            </small>
          </div>

          <span className={`tag ${audit?.current_status||selectedRule.validation_status||selectedRule.status}`}>
            {audit?.current_status||selectedRule.validation_status||selectedRule.status||"draft"}
          </span>
        </div>

        {role!=="Monitor"&&(
          <div className="ruleLifecycleActions">
            {(audit?.current_status||selectedRule.validation_status||selectedRule.status||"draft")==="draft"&&(
              <button
                className="lifecycleAction lifecycleValidate"
                disabled={busy}
                onClick={()=>transitionRule(selectedRule,"validated")}
              >
                <span className="lifecycleActionDot"/>
                Validate rule
              </button>
            )}

            {(audit?.current_status||selectedRule.validation_status||selectedRule.status)==="validated"&&(
              <button
                className="lifecycleAction lifecycleApprove"
                disabled={busy}
                onClick={()=>transitionRule(selectedRule,"approved")}
              >
                <span className="lifecycleActionDot"/>
                Approve rule
              </button>
            )}

            {(audit?.current_status||selectedRule.validation_status||selectedRule.status)==="approved"&&(
              <button
                className="lifecycleAction lifecycleActivate"
                disabled={busy}
                onClick={()=>transitionRule(selectedRule,"active")}
              >
                <span className="lifecycleActionDot"/>
                Activate hunt
              </button>
            )}
          </div>
        )}

        {auditLoading ? (
          <div className="emptyState">Loading lifecycle history…</div>
        ) : audit?.history?.length ? (
          <div className="auditTimeline">
            {audit.history.map((event,index)=>(
              <details
                className="auditTimelineItem auditTimelineDetails"
                key={event.id||index}
              >
                <summary className="auditTimelineSummary">
                  <div className="auditTimelineMarker">
                    <i/>
                    {index<audit.history.length-1&&<span/>}
                  </div>

                  <div className="auditTimelineSummaryMain">
                    <div className="auditTimelineSummaryTitle">
                      <b>
                        {event.new_status
                          ? event.new_status.charAt(0).toUpperCase()+event.new_status.slice(1)
                          : "Lifecycle update"}
                      </b>
                      <span className="auditTimelineChevron">⌄</span>
                    </div>

                    <div className="auditTimelineSummaryMeta">
                      <span>
                        {event.reason||"Lifecycle state changed"}
                      </span>
                      <time>
                        {event.changed_at
                          ?new Date(event.changed_at).toLocaleString()
                          :"—"}
                      </time>
                    </div>
                  </div>
                </summary>

                <div className="auditTimelineContent">
                  <div className="auditDetailGrid">
                    <div>
                      <small>Transition</small>
                      <b>
                        {event.previous_status||"—"}
                        <span>→</span>
                        {event.new_status||"—"}
                      </b>
                    </div>

                    <div>
                      <small>Actor</small>
                      <b>{event.changed_by||"system"}</b>
                    </div>

                    <div>
                      <small>Source</small>
                      <b>{event.source||"—"}</b>
                    </div>

                    <div>
                      <small>Time</small>
                      <b>
                        {event.changed_at
                          ?new Date(event.changed_at).toLocaleString()
                          :"—"}
                      </b>
                    </div>
                  </div>

                  {event.reason&&(
                    <div className="auditReason">
                      <small>Review note</small>
                      <p>{event.reason}</p>
                    </div>
                  )}
                </div>
              </details>
            ))}
          </div>
        ) : (
          <div className="auditCurrentState">
            <span className="auditStateDot"/>
            <div>
              <b>No recorded transitions yet</b>
              <small>
                Current lifecycle state is{" "}
                <strong>
                  {audit?.current_status||selectedRule.validation_status||selectedRule.status||"draft"}
                </strong>.
              </small>
            </div>
          </div>
        )}
      </div>
    )}

    {campaign?.findings?.length ? (
      <div className="campaignSubsection">
        <div className="sectionTitleRow">
          <div>
            <h3>Findings</h3>
            <small>Findings returned by the current hunt execution.</small>
          </div>
        </div>

        <div className="campaignFindings">
          {campaign.findings.map((f,i)=>(
            <div className="campaignFinding" key={f.id||i}>
              <b>{f.rule_title||f.title||"Finding"}</b>
              <span>{f.verification_status||f.severity||"Unverified"}</span>
            </div>
          ))}
        </div>
      </div>
    ) : null}

    <div className="simulationNotice">
      <b>Evaluation mode: {campaign?.mode||"simulation"}</b>
      <span>
        This investigation is evaluated against available telemetry. Live SIEM
        execution is not enabled in this environment.
      </span>
    </div>
  </div>;
}

function GlobalSearch({onClose,go,open}) {
  const [q,setQ]=useState(""), [findings,setFindings]=useState([]),[campaigns,setCampaigns]=useState([]),[rules,setRules]=useState([]);
  useEffect(()=>{api("/findings?page_size=100").then(x=>x?.items&&setFindings(x.items)).catch(()=>{});api("/campaigns").then(x=>Array.isArray(x)&&setCampaigns(x)).catch(()=>{});api("/sigma/rules?page_size=100").then(x=>setRules(x?.items||x||FALLBACK_RULES)).catch(()=>{})},[]);
  const all=[...campaigns.map(x=>({type:"campaign",label:x.name,meta:`Campaign · CMP-${x.id}`,data:x})),...findings.map(x=>({type:"finding",label:x.rule_title,meta:`Finding · ${x.finding_id}`,data:x})),...rules.map(x=>({type:"rule",label:x.title,meta:`Detection · ${x.rule_id}`,data:x})),...FALLBACK_TECHNIQUES.map(x=>({type:"technique",label:x.name,meta:`ATT&CK · ${x.attack_id}`,data:x}))];
  const results=all.filter(x=>`${x.label} ${x.meta}`.toLowerCase().includes(q.toLowerCase())).slice(0,12);
  return <div className="commandOverlay" onMouseDown={e=>e.target===e.currentTarget&&onClose()}><div className="command"><input autoFocus placeholder="Search campaigns, findings, detections, ATT&CK…" value={q} onChange={e=>setQ(e.target.value)}/><div className="commandHint">Esc to close · Enter to open result</div>{results.map((r,i)=><button key={i} onClick={()=>{open(r);onClose()}}><b>{r.label}</b><small>{r.meta}</small><span>→</span></button>)}</div></div>;
}

function RiskCenter({close,go,open}) {
  const [items,setItems]=useState(null),[tab,setTab]=useState("all");
  useEffect(()=>{api("/findings?page=1&page_size=60").then(x=>setItems(x.items||[])).catch(()=>setItems([]))},[]);
  const tabs=[["all","All"],["risk","High risk"],["review","Needs review"],["fp","Dismissed"]];
  const list=(items||[]).filter(f=>tab==="all"||(tab==="risk"&&f.label==="high")||(tab==="review"&&f.verification_status==="unverified")||(tab==="fp"&&f.verification_status==="dismissed")).sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,25);
  return <div className="commandOverlay" onMouseDown={e=>e.target===e.currentTarget&&close()}><div className="riskPanel"><div className="drawerHead"><div><small>RISK CENTER</small><h2>Alerts & operational risk</h2></div><button onClick={close}>×</button></div>
    <div className="riskTabs">{tabs.map(([k,l])=><button key={k} className={tab===k?"active":""} onClick={()=>setTab(k)}>{l}</button>)}</div>
    {items===null&&<div className="emptyState">Loading findings…</div>}
    {items&&!list.length&&<div className="emptyState">Nothing in this view.</div>}
    {list.map(f=><button className="alertRow" key={f.finding_id} onClick={()=>{open({type:"finding",data:f});close()}}><span className={`severity ${f.label}`}>{f.label}</span><div><b>{f.rule_title}</b><small>Risk {f.risk_score} · {f.verification_status} · {(f.attack_technique_ids||[]).join(", ")}</small></div><span>→</span></button>)}
  </div></div>;
}

function App() {
  const [session,setSession]=useState(()=>{try{return JSON.parse(localStorage.getItem("threathunt_session")||"null")}catch{return null}});
  const [page,setPage]=useState("overview"),[detail,setDetail]=useState(null),[theme,setTheme]=useState(localStorage.getItem("th_theme")||"system"),[toast,setToast]=useState(""),[search,setSearch]=useState(false),[risk,setRisk]=useState(false),[profile,setProfile]=useState(false),[menu,setMenu]=useState(false),[collapsed,setCollapsed]=useState(localStorage.getItem("th_sidebar_collapsed")==="1"),[side,setSide]=useState(localStorage.getItem("th_sidebar_side")||"left");
  const [findingCount,setFindingCount]=useState(0);
  useEffect(()=>{const h=()=>setSession(null);window.addEventListener("th-session-expired",h);return()=>window.removeEventListener("th-session-expired",h)},[]);

  useEffect(()=>{
    if(!session)return;
    let alive=true;
    api("/findings?page=1&page_size=1")
      .then(x=>{
        if(alive)setFindingCount(Number(x?.total)||0);
      })
      .catch(()=>{
        if(alive)setFindingCount(0);
      });
    return()=>{alive=false};
  },[session]);

  const openDetail=async d=>{
    if(d?.type==="finding"&&d?.data?.finding_id){
      try{
        const full=await api(`/findings/${encodeURIComponent(d.data.finding_id)}`);
        setDetail({type:"finding",data:{...d.data,...full}});
        return;
      }catch{}
    }
    setDetail(d);
  };
  const notify=m=>{setToast(m);setTimeout(()=>setToast(""),2600)};
  useEffect(()=>{document.documentElement.dataset.theme=theme;localStorage.setItem("th_theme",theme)},[theme]);
  useEffect(()=>{localStorage.setItem("th_sidebar_collapsed",collapsed?"1":"0")},[collapsed]);
  useEffect(()=>{localStorage.setItem("th_sidebar_side",side)},[side]);
  useEffect(()=>{const h=e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="k"){e.preventDefault();setSearch(true)}if(e.key==="/"&&!["INPUT","TEXTAREA","SELECT"].includes(e.target?.tagName)){e.preventDefault();setSearch(true)}if(e.key==="Escape"){setSearch(false);setRisk(false);setProfile(false);setMenu(false);setDetail(null)}};window.addEventListener("keydown",h);return()=>window.removeEventListener("keydown",h)},[]);
  if(!session)return <Login theme={theme} setTheme={setTheme} onLogin={s=>{setSession(s);localStorage.setItem("threathunt_session",JSON.stringify(s))}}/>;
  const isAdmin=session.role==="Administrator", isAnalyst=session.role==="Analyst"||isAdmin;
  const nav=[["--","Operations"],["overview","Overview"],["campaigns","Campaigns"],["findings","Findings"],["reports","Reports"],["--","Intelligence"],["hypotheses","Hypothesis Engine"],["attack","ATT&CK Explorer"],["detections","Detections"],["generator","Rule Generator"],["--","Platform"],["context","Inputs Context"],["datasets","Data Sources"],["pipeline","Pipeline"],...(isAdmin?[["admin","Administration"]]:[])];
  const go=p=>{setPage(p);setDetail(null);setProfile(false);setMenu(false)};
  const logout=()=>{localStorage.removeItem("threathunt_session");setSession(null)};
  return <div className={`app ${collapsed?"collapsed":""} side-${side}`}>
    <aside className="sidebar"><div className="brand"><div className="logo">TH</div><div className="brandWords"><b>ThreatHunt</b><small>security operations</small></div><button onClick={()=>setCollapsed(x=>!x)}>{collapsed?"›":"‹"}</button></div>
      <nav>{nav.map(([id,label])=>id==="--"?<div key={label} className="navSec">{label}</div>:<button key={id} className={page===id?"active":""} onClick={()=>go(id)}><b>{label}</b>{id==="findings"&&<em>{findingCount}</em>}</button>)}</nav>
      <div className="sidebarBottom"><div className="health"><i/> <span><b>Platform healthy</b><small>Core services operational</small></span></div><div className="profileWrap"><button className="profileBtn" onClick={()=>setProfile(x=>!x)}><div className="avatar">{initials(session.name)}</div><span><b>{session.name}</b><small>{session.role}</small></span><strong>⋮</strong></button>{profile&&<div className="popover profilePop"><button onClick={()=>go("overview")}>Profile overview</button><button onClick={()=>notify("Preferences are available in workspace settings.")}>Preferences</button><button onClick={()=>notify("Activity is represented by the audit trail in Administration.")}>Activity</button><button onClick={()=>notify("Shortcuts: Ctrl+K search · / search · Esc close")}>Keyboard shortcuts</button><button className="danger" onClick={logout}>Sign out</button></div>}</div></div>
    </aside>
    <main><header><div className="crumb"><span>ThreatHunt</span><b>/</b><strong>{nav.find(x=>x[0]===page)?.[1]||"Investigation"}</strong></div><div className="topActions"><button title="Move sidebar" onClick={()=>setSide(x=>x==="left"?"right":"left")}>↔</button><div className="theme"><button className={theme==="light"?"active":""} onClick={()=>setTheme("light")}>☼</button><button className={theme==="dark"?"active":""} onClick={()=>setTheme("dark")}>◐</button><button className={theme==="system"?"active":""} onClick={()=>setTheme("system")}>◌</button></div><button title="Search" onClick={()=>setSearch(true)}>⌕</button><button title="Risk Center" onClick={()=>setRisk(true)}>◔</button><button className="topAvatar" onClick={()=>setProfile(x=>!x)}>{initials(session.name)}</button><button className="headerSignOut" title="Sign out" onClick={logout}>Sign out</button><button onClick={()=>setMenu(x=>!x)}>⋯</button>{menu&&<div className="popover menuPop"><button onClick={()=>notify("Workspace overview refreshed.")}>Refresh data</button><button onClick={()=>notify("Export workflow is ready from object views.")}>Export</button><button onClick={()=>notify("Workspace: ThreatHunt Security Operations")}>Workspace</button><button onClick={()=>notify("System status: operational.")}>System status</button><button onClick={()=>notify("Use Ctrl+K or / for global search.")}>Help</button></div>}</div></header>
      <div className="content">
        {page==="overview"&&<Overview role={session.role} go={go} open={openDetail}/>}
        {page==="campaigns"&&<Campaigns role={session.role} go={go} open={openDetail} notify={notify}/>}
        {page==="findings"&&<Findings open={openDetail}/>}
        {page==="detections"&&<Detections role={session.role} open={openDetail}/>}
        {page==="generator"&&<Generator role={session.role} notify={notify}/>}
        {page==="attack"&&<Attack open={openDetail}/>}
        {page==="hypotheses"&&<Hypotheses open={openDetail}/>}
        {page==="datasets"&&<Datasets role={session.role}/>}
        {page==="reports"&&<Reports role={session.role} notify={notify}/>}
        {page==="context"&&<InputsContext role={session.role} notify={notify}/>}

        {page==="pipeline"&&<Pipeline role={session.role} notify={notify}/>}
        {page==="admin"&&isAdmin&&<Admin session={session} notify={notify}/>}
      </div>
    </main>
    {detail&&<ObjectDrawer detail={detail} role={session.role} close={()=>setDetail(null)} notify={notify} open={openDetail}/>}
    {search&&<GlobalSearch onClose={()=>setSearch(false)} go={go} open={setDetail}/>}
    {risk&&<RiskCenter close={()=>setRisk(false)} go={go} open={setDetail}/>}
    {toast&&<div className="toast">✓ {toast}</div>}
  </div>;
}

createRoot(document.getElementById("root")).render(<App/>);
