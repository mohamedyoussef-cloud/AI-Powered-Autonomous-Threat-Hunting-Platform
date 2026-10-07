#!/usr/bin/env python3
import csv, hashlib, json, re
from collections import Counter
from pathlib import Path

ROOT=Path(r'D:\ThreatHunting\project')
P3=ROOT/'data'/'processed'/'phase3'
PLAN=P3/'detection_plan'/'detection_plan_baseline_dispatch_v1.jsonl'
RT=P3/'splunk_runtime'
LIVE=RT/'sourcetype_inventory.csv'
REL=RT/'source_sourcetype_inventory.csv'
TASKS=RT/'telemetry_resolution_ai_tasks_v2.jsonl'
CAND=RT/'telemetry_resolution_candidates.json'
AUD=RT/'ai_resolution_audit'/'telemetry_resolution'/'output'
BASE=AUD/'qwen_base_resolver_v1'/'predictions.jsonl'
LORA=AUD/'qwen_resolver_v1'/'predictions.jsonl'
OUT=RT/'evidence_gate'
SRC_OUT=OUT/'telemetry_source_resolution_v1.jsonl'
PATH_OUT=OUT/'grounded_path_runtime_resolution_v1.jsonl'
SUMMARY=OUT/'summary_v1.json'
MANIFEST=OUT/'manifest_v1.json'

STOP={'win','event','log','wineventlog','xmlwineventlog','microsoft','windows','operational','logs','with','advanced','the','and','security','audit','office','system','application','aws','m365','etw','core','com'}

def read_jsonl(p):
    out=[]
    with Path(p).open(encoding='utf-8-sig') as f:
        for n,line in enumerate(f,1):
            line=line.strip()
            if line:
                try: out.append(json.loads(line))
                except Exception as e: raise RuntimeError(f'{p}:{n}: {e}')
    return out

def compact(s): return re.sub(r'[^a-z0-9]','',str(s).lower())
def toks(s): return {x for x in re.findall(r'[a-z0-9]+',str(s).lower()) if len(x)>=4 and x not in STOP}
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()
def ai_index(p):
    d={}
    for r in read_jsonl(p):
        q=r.get('parsed_output') if isinstance(r.get('parsed_output'),dict) else {}
        d[r['logical_source']]={'validation_status':r.get('validation_status'),'validation_errors':r.get('validation_errors',[]),'decision':q.get('decision'),'selected_sourcetype':q.get('selected_sourcetype'),'confidence':q.get('confidence')}
    return d

def main():
    req=[PLAN,LIVE,REL,TASKS,CAND,BASE,LORA]
    miss=[str(p) for p in req if not p.exists()]
    if miss: raise RuntimeError('Missing inputs:\n'+'\n'.join(miss))
    OUT.mkdir(parents=True,exist_ok=True)

    plans=read_jsonl(PLAN); tasks=read_jsonl(TASKS); base=ai_index(BASE); lora=ai_index(LORA)
    with LIVE.open(encoding='utf-8-sig',newline='') as f: live=list(csv.DictReader(f))
    with REL.open(encoding='utf-8-sig',newline='') as f: rel=list(csv.DictReader(f))
    if len(live)!=107: raise RuntimeError(f'Expected 107 live sourcetypes, got {len(live)}')
    if len(rel)!=1100: raise RuntimeError(f'Expected 1100 relationships, got {len(rel)}')

    ready=[r for r in plans if r.get('deterministic_resolution',{}).get('plan_status')=='READY_FOR_BASELINE_SIGMA']
    gps=[(r,p) for r in ready for p in r.get('deterministic_resolution',{}).get('grounded_paths',[])]
    if len(ready)!=492 or len(gps)!=540: raise RuntimeError(f'Unexpected population READY={len(ready)} PATHS={len(gps)}')
    logical=sorted({s for _,p in gps for s in p.get('log_sources',[])})
    if len(logical)!=25: raise RuntimeError(f'Expected 25 logical sources, got {len(logical)}')

    by_comp={compact(x['sourcetype']):x for x in live}; live_names={x['sourcetype'] for x in live}; task_by={x['logical_source']:x for x in tasks}
    tokmap={}
    for x in live:
        st=x['sourcetype']
        for t in set(re.findall(r'[a-z0-9]+',st.lower())): tokmap.setdefault(t,set()).add(st)

    results=[]
    for src in logical:
        status=selected=method=None; evidence=[]
        if compact(src) in by_comp:
            x=by_comp[compact(src)]; selected=x['sourcetype']; status='CONFIRMED'; method='DETERMINISTIC_NORMALIZED_EXACT'; evidence=[{'type':'live_exact_match','sourcetype':selected,'event_count':int(x['count'])}]
        if status is None:
            hits=[]
            for t in sorted(toks(src)):
                sts=tokmap.get(t,set())
                if len(sts)==1: hits.append((t,next(iter(sts))))
            uniq=sorted({st for _,st in hits})
            if len(uniq)==1:
                selected=uniq[0]; x=next(r for r in live if r['sourcetype']==selected); status='CONFIRMED'; method='DETERMINISTIC_UNIQUE_DISTINCTIVE_TOKEN'; evidence=[{'type':'unique_distinctive_token','tokens':[t for t,st in hits if st==selected],'sourcetype':selected,'event_count':int(x['count'])}]
        if status is None:
            b=base.get(src,{}); l=lora.get(src,{})
            if b.get('validation_status')=='PASS' and l.get('validation_status')=='PASS' and b.get('decision')=='MATCH' and l.get('decision')=='MATCH' and b.get('selected_sourcetype')==l.get('selected_sourcetype') and b.get('selected_sourcetype') in live_names:
                selected=b['selected_sourcetype']; x=next(r for r in live if r['sourcetype']==selected); status='CONFIRMED'; method='AI_AGREEMENT_WITH_LIVE_CANDIDATE'; evidence=[{'type':'base_lora_agreement','sourcetype':selected,'event_count':int(x['count']),'base_confidence':b.get('confidence'),'lora_confidence':l.get('confidence')}]
        if status is None:
            b=base.get(src,{}); l=lora.get(src,{}); task=task_by.get(src,{})
            src_all={x for x in re.findall(r'[a-z0-9]+',src.lower()) if len(x)>=4 and x not in {'win','event','log','wineventlog','xmlwineventlog','microsoft','windows','operational','logs','with','advanced','the','and','system','application'}}
            evc=[]
            for c in task.get('allowed_live_candidates',[]):
                text=c['sourcetype']+' '+' '.join(z.get('source','') for z in c.get('source_examples',[]))
                ov=sorted(src_all & set(re.findall(r'[a-z0-9]+',text.lower())))
                if ov: evc.append({'sourcetype':c['sourcetype'],'event_count':int(c['event_count']),'overlap_tokens':ov})
            aipos=[]
            for name,r in [('base',b),('sigma_lora',l)]:
                if r.get('validation_status')=='PASS' and r.get('decision') in {'MATCH','AMBIGUOUS'}:
                    aipos.append({'model':name,'decision':r.get('decision'),'selected_sourcetype':r.get('selected_sourcetype'),'confidence':r.get('confidence')})
            if evc or aipos:
                status='AMBIGUOUS'; method='INSUFFICIENT_CORROBORATION'
                if evc: evidence.append({'type':'live_candidate_overlap','candidates':evc[:10]})
                if aipos: evidence.append({'type':'valid_ai_positive_but_uncorroborated','outputs':aipos})
            else:
                status='UNAVAILABLE'; method='NO_CREDIBLE_LIVE_EQUIVALENT'; evidence=[{'type':'live_inventory_checked','live_sourcetypes':len(live),'relationships':len(rel)}]
        results.append({'resolver_gate_version':'1.0','logical_source':src,'status':status,'selected_sourcetype':selected,'resolution_method':method,'evidence':evidence,'base_qwen':base.get(src),'sigma_lora_qwen':lora.get(src)})

    idx={r['logical_source']:r for r in results}
    with SRC_OUT.open('w',encoding='utf-8') as f:
        for r in results: f.write(json.dumps(r,ensure_ascii=False)+'\n')

    path_rows=[]
    for plan,p in gps:
        sr=[idx[s] for s in p.get('log_sources',[])]
        confirmed=sorted({r['selected_sourcetype'] for r in sr if r['status']=='CONFIRMED' and r['selected_sourcetype']})
        unresolved=[{'logical_source':r['logical_source'],'status':r['status']} for r in sr if r['status']!='CONFIRMED']
        cov='ALL_SOURCES_CONFIRMED' if confirmed and not unresolved else ('PARTIAL_SOURCE_COVERAGE' if confirmed else 'NO_CONFIRMED_SOURCE')
        path_rows.append({'resolver_gate_version':'1.0','technique_id':plan['technique_id'],'technique_name':plan.get('technique_name'),'path_id':p['path_id'],'analytic_id':p.get('analytic_id'),'logical_log_sources':p.get('log_sources',[]),'confirmed_sourcetypes':confirmed,'unresolved_sources':unresolved,'source_coverage_state':cov,'event_ids':p.get('event_ids',[]),'evidence_ids':p.get('evidence_ids',[]),'requirement_ids':p.get('requirement_ids',[]),'field_bindings':p.get('field_bindings',[]),'grounding_status':p.get('grounding_status')})
    with PATH_OUT.open('w',encoding='utf-8') as f:
        for r in path_rows: f.write(json.dumps(r,ensure_ascii=False)+'\n')

    sc=Counter(r['status'] for r in results); pc=Counter(r['source_coverage_state'] for r in path_rows)
    summary={'resolver_gate_version':'1.0','logical_sources':len(results),'source_status_counts':dict(sorted(sc.items())),'ready_plans':len(ready),'grounded_paths':len(path_rows),'path_source_coverage_counts':dict(sorted(pc.items())),'live_sourcetypes':len(live),'live_source_sourcetype_relationships':len(rel),'policy':{'confirmed_requires':['normalized exact live match','or unique distinctive token in live sourcetype name','or contract-valid base+LoRA agreement on same allowed live candidate'],'ambiguous':'positive evidence exists but is not sufficiently corroborated','unavailable':'no credible equivalent observed in current live inventory','occurrence_claim':False}}
    SUMMARY.write_text(json.dumps(summary,indent=2,ensure_ascii=False),encoding='utf-8')
    manifest={'inputs':{str(p):sha(p) for p in req},'outputs':{str(SRC_OUT):sha(SRC_OUT),str(PATH_OUT):sha(PATH_OUT),str(SUMMARY):sha(SUMMARY)}}
    MANIFEST.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print('LOGICAL_SOURCES',len(results)); print('SOURCE_STATUS_COUNTS',dict(sorted(sc.items()))); print('GROUNDED_PATHS',len(path_rows)); print('PATH_SOURCE_COVERAGE_COUNTS',dict(sorted(pc.items()))); print('SOURCE_OUTPUT',SRC_OUT); print('PATH_OUTPUT',PATH_OUT); print('SUMMARY',SUMMARY); print('MANIFEST',MANIFEST)

if __name__=='__main__': main()
