#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
estatistica.py — agrega as REPETIÇÕES por cenário e IDS e calcula intervalos de
confiança (campanha02). Preenche a lacuna do metricas.py (que trata cada janela
como independente e não agrega repetições).

Lê classificacao_detalhe.csv (um registro por janela+IDS, já com o rótulo TP /
ERRO_CLASSIF / FN_PURO / FP / TN) e execucoes.csv (contagens de alertas por janela).

Para cada (cenario, ids):
  cenário malicioso:
     n           = nº de repetições (janelas)
     taxa_det    = TP / n                (detecção com assinatura CORRETA)
     ic95        = intervalo de Wilson 95% para taxa_det
     taxa_erro   = ERRO_CLASSIF / n      (detectou família errada)
     taxa_fn     = FN_PURO / n
  cenário benigno:
     taxa_fp     = FP / n
  alertas_media/dp = média e desvio-padrão amostral da contagem de alertas por janela.

Uso: python3 estatistica.py <classificacao_detalhe.csv> <execucoes.csv> <dir_saida>
Sem dependências externas (só stdlib).
"""
import csv, sys, os, math
from collections import defaultdict

Z = 1.96  # 95%

def wilson(k, n, z=Z):
    """IC de Wilson p/ proporção k/n. Retorna (low, high)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z*z/n
    centro = (p + z*z/(2*n)) / d
    metade = (z * math.sqrt(p*(1-p)/n + z*z/(4*n*n))) / d
    return (max(0.0, centro - metade), min(1.0, centro + metade))

def media_dp(xs):
    n = len(xs)
    if n == 0:
        return (0.0, 0.0)
    m = sum(xs)/n
    if n < 2:
        return (m, 0.0)
    var = sum((x-m)**2 for x in xs)/(n-1)
    return (m, math.sqrt(var))

def f(x):
    return "nan" if isinstance(x, float) and math.isnan(x) else f"{x:.3f}"

def main():
    if len(sys.argv) < 4:
        print("uso: estatistica.py <classificacao_detalhe.csv> <execucoes.csv> <dir_saida>")
        sys.exit(2)
    detalhe_csv, exec_csv, outdir = sys.argv[1:4]
    os.makedirs(outdir, exist_ok=True)

    detalhe = list(csv.DictReader(open(detalhe_csv, encoding="utf-8")))
    execs = {r["execucao_id"]: r for r in csv.DictReader(open(exec_csv, encoding="utf-8"))}

    # agrupa rótulos por (cenario, classe, ids)
    grupos = defaultdict(list)   # (cen, classe, ids) -> [rotulo,...]
    contagens = defaultdict(list)  # (cen, classe, ids) -> [n_alertas por janela]
    for d in detalhe:
        key = (d["cenario"], d["classe"], d["ids"])
        grupos[key].append(d["rotulo"])
        ex = execs.get(d["execucao_id"])
        if ex:
            contagens[key].append(int(ex.get(d["ids"], 0) or 0))

    linhas = []
    for (cen, classe, ids) in sorted(grupos):
        rots = grupos[(cen, classe, ids)]
        n = len(rots)
        cont = contagens[(cen, classe, ids)]
        amed, adp = media_dp([float(x) for x in cont])
        if classe.startswith("malic"):
            tp = rots.count("TP"); err = rots.count("ERRO_CLASSIF"); fnp = rots.count("FN_PURO")
            low, high = wilson(tp, n)
            linhas.append(dict(cenario=cen, classe=classe, ids=ids, n=n,
                taxa_det=tp/n if n else 0.0, det_ic95_low=low, det_ic95_high=high,
                taxa_erro_classif=err/n if n else 0.0, taxa_fn_puro=fnp/n if n else 0.0,
                taxa_fp="", alertas_media=amed, alertas_dp=adp))
        else:
            fp = rots.count("FP")
            low, high = wilson(fp, n)
            linhas.append(dict(cenario=cen, classe=classe, ids=ids, n=n,
                taxa_det="", det_ic95_low="", det_ic95_high="",
                taxa_erro_classif="", taxa_fn_puro="",
                taxa_fp=fp/n if n else 0.0, alertas_media=amed, alertas_dp=adp))

    cols = ["cenario","classe","ids","n","taxa_det","det_ic95_low","det_ic95_high",
            "taxa_erro_classif","taxa_fn_puro","taxa_fp","alertas_media","alertas_dp"]
    with open(os.path.join(outdir, "estatistica.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for r in linhas:
            w.writerow([r["cenario"], r["classe"], r["ids"], r["n"],
                        f(r["taxa_det"]) if r["taxa_det"] != "" else "",
                        f(r["det_ic95_low"]) if r["det_ic95_low"] != "" else "",
                        f(r["det_ic95_high"]) if r["det_ic95_high"] != "" else "",
                        f(r["taxa_erro_classif"]) if r["taxa_erro_classif"] != "" else "",
                        f(r["taxa_fn_puro"]) if r["taxa_fn_puro"] != "" else "",
                        f(r["taxa_fp"]) if r["taxa_fp"] != "" else "",
                        f(r["alertas_media"]), f(r["alertas_dp"])])

    print("=== estatistica.py ===")
    print(f"{'cenario':20} {'classe':9} {'ids':9} {'n':>3} {'det':>6} {'IC95':>15} {'errCl':>6} {'fn':>6} {'fp':>6}")
    for r in linhas:
        ic = f"[{f(r['det_ic95_low'])},{f(r['det_ic95_high'])}]" if r["det_ic95_low"] != "" else "-"
        det = f(r["taxa_det"]) if r["taxa_det"] != "" else "-"
        err = f(r["taxa_erro_classif"]) if r["taxa_erro_classif"] != "" else "-"
        fnp = f(r["taxa_fn_puro"]) if r["taxa_fn_puro"] != "" else "-"
        fp  = f(r["taxa_fp"]) if r["taxa_fp"] != "" else "-"
        print(f"{r['cenario']:20} {r['classe']:9} {r['ids']:9} {r['n']:>3} {det:>6} {ic:>15} {err:>6} {fnp:>6} {fp:>6}")
    print(f"Saída: {outdir}/estatistica.csv")

if __name__ == "__main__":
    main()
