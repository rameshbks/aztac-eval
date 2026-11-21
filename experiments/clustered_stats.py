"""Task-clustered statistics for E2: bootstrap over user tasks within each suite (4,000 resamples),
paired differences and exact McNemar tests on identical (user, injection) pairs.
Usage: python experiments/clustered_stats.py results/e2_gpt4omini.jsonl
"""
import json, sys, random, collections, math
from scipy.stats import binomtest
R=[json.loads(l) for l in open(sys.argv[1])]
DEF=['none','spotlighting_with_delimiting','repeat_user_prompt','tool_filter','aztac-llm','aztac-llm+spotlighting','aztac-oracle']
att=collections.defaultdict(dict)   # defense -> (suite,ut,it) -> (exec, util)
ben=collections.defaultdict(dict)
for r in R:
    k=(r['suite'],r['user_task'],r['injection_task'])
    if r['injection_task']: att[r['defense']][k]=(bool(r.get('attack_success_executed')),bool(r['utility']))
    else: ben[r['defense']][k]=bool(r['utility'])
pairs=sorted(att['none'])
clusters=collections.defaultdict(list)
for k in pairs: clusters[(k[0],k[1])].append(k)
bysuite=collections.defaultdict(list)
for c in clusters: bysuite[c[0]].append(c)
rng=random.Random(0); B=4000
def boot(fn):
    vals=[]
    for _ in range(B):
        ks=[]
        for s,cs in bysuite.items():
            for c in (rng.choice(cs) for _ in cs): ks+=clusters[c]
        vals.append(fn(ks))
    vals.sort(); return vals[int(.025*B)], vals[int(.975*B)]
out={}
for d in DEF:
    f=lambda ks,d=d: 100*sum(att[d][k][0] for k in ks)/len(ks)
    lo,hi=boot(f); out[d]=(f(pairs),lo,hi)
    print(f"{d:28s} ASR_exec {f(pairs):5.1f}  cluster95 [{lo:.1f}, {hi:.1f}]")
print("\nPaired vs aztac-llm (same 589 pairs): diff = baseline - aztac, cluster CI, exact McNemar")
for d in DEF:
    if d=='aztac-llm': continue
    f=lambda ks,d=d: 100*(sum(att[d][k][0] for k in ks)-sum(att['aztac-llm'][k][0] for k in ks))/len(ks)
    lo,hi=boot(f)
    b=sum(1 for k in pairs if att[d][k][0] and not att['aztac-llm'][k][0]); c=sum(1 for k in pairs if att['aztac-llm'][k][0] and not att[d][k][0])
    p=binomtest(b,b+c,0.5).pvalue if b+c else 1
    print(f"{d:28s} diff {f(pairs):5.1f} [{lo:.1f}, {hi:.1f}]  discordant b={b} c={c} p={p:.2g}")
# benign utility paired
print("\nBenign utility paired vs none (97 tasks)")
bk=sorted(ben['none'])
for d in DEF:
    lost=sum(1 for k in bk if ben['none'][k] and not ben[d][k]); gain=sum(1 for k in bk if ben[d][k] and not ben['none'][k])
    p=binomtest(lost,lost+gain,0.5).pvalue if lost+gain else 1
    print(f"{d:28s} {100*sum(ben[d].values())/len(bk):.1f}  lost {lost} gained {gain} p={p:.2g}")
