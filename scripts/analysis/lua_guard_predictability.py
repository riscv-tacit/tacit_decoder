#!/usr/bin/env python3
"""Is a shipped guard's OUTCOME predictable from handler history?

For each guard (f -> g), takes the boolean (next == g) over the dispatch_seq stream and
reports its predictability under k-deep handler history: sum over contexts of
max(hits, misses) / total. That is the ceiling for the conditional predictor that now
decides the dispatch; `share` is what an always-not-taken guard scores. Run from the
tacit_decoder directory. See software/lua-dispatch/reports/dispatch-fused.md section 3(d).
"""
import json
import numpy as np, pandas as pd
D='/scratch/iansseijelly/tacit-chipyard/software/tacit_decoder'
NCJ=json.load(open(f'{D}/configs/lua/lua_optab_ncj.json'))
nm={int(a,16):n for a,n in NCJ.items()}
SEQ={'nbody':'trace.lua-ncj-nbody.dispatch_seq.csv','fannkuch':'trace.lua-ncj-fannkuch.dispatch_seq.csv',
     'fasta':'trace.lua-micro-fasta.dispatch_seq.csv','mandelbrot':'trace.lua-micro-mandelbrot.dispatch_seq.csv',
     'queens':'trace.lua-micro-queens.dispatch_seq.csv','spectralnorm':'trace.lua-micro-spectralnorm.dispatch_seq.csv'}
GUARDS={'fused':[('GETTABLE','GETTABLE'),('GETFIELD','GETFIELD'),('SETTABLE','ADDI'),('ADDI','LE')],
        'fused3':[('LOADI','FORPREP'),('ADDI','GETTABLE'),('ADD','MOVE'),('MUL','MUL'),('LT','GETTABLE'),('TEST','GETUPVAL')]}
VAR={'nbody':'fused','fannkuch':'fused','fasta':'fused3','mandelbrot':'fused3','queens':'fused3','spectralnorm':'fused3'}
# measured post-fusion entry mean where the instrument stayed intact (else None)
MEAS={('fannkuch','SETTABLE','ADDI'):(10.29,12.17),('fasta','LOADI','FORPREP'):(16.68,3.84),
      ('fasta','LT','GETTABLE'):(13.76,5.73),('queens','LOADI','FORPREP'):(18.16,3.33),
      ('queens','TEST','GETUPVAL'):(23.75,9.39),('spectralnorm','TEST','GETUPVAL'):(13.59,14.94)}
print(f"{'bench':13s} {'guard f -> g':24s} {'exits':>10s} {'share':>6s} {'pred@o1':>8s} {'pred@o2':>8s} "
      f"{'pred@o3':>8s} {'pred@o4':>8s} | {'measured entry mean':>20s}")
for b,f in SEQ.items():
    c=pd.read_csv(f'{D}/{f}',usecols=['to_handler'])['to_handler'].astype('category')
    cats=[nm.get(int(s.strip(),16),s.strip()) for s in c.cat.categories]
    v=c.cat.codes.to_numpy().astype(np.int64); K=len(cats); del c
    idx={n:i for i,n in enumerate(cats)}
    for (fh,gh) in GUARDS[VAR[b]]:
        if fh not in idx or gh not in idx: continue
        fi,gi=idx[fh],idx[gh]
        sel=np.nonzero(v[:-1]==fi)[0]           # positions where handler f runs
        if len(sel)<10000: continue
        hit=(v[sel+1]==gi)
        share=hit.mean()
        preds=[]
        for k in (1,2,3,4):
            ok=sel[sel>=k-1]
            h=np.zeros(len(ok),dtype=np.int64)
            for j in range(k):                   # context = k handlers ending at f
                h=h*K+v[ok-(k-1-j)]
            hh=(v[ok+1]==gi)
            key=h*2+hh
            cnt=np.bincount(key)
            nz=np.nonzero(cnt)[0]; ctx=nz//2
            mx=np.zeros(int(ctx.max())+1,dtype=np.int64)
            np.maximum.at(mx,ctx,cnt[nz])
            preds.append(mx.sum()/cnt.sum())
        m=MEAS.get((b,fh,gh))
        ms=f"{m[0]:.2f} -> {m[1]:.2f}" if m else "invisible"
        print(f"{b:13s} {fh+' -> '+gh:24s} {len(sel):10,d} {100*share:5.1f}% "
              f"{100*preds[0]:7.1f}% {100*preds[1]:7.1f}% {100*preds[2]:7.1f}% {100*preds[3]:7.1f}% | {ms:>20s}")
    del v
