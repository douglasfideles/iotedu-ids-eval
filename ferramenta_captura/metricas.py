#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
metricas.py — calcula métricas de eficácia de detecção a partir de execucoes.csv.

Unidade de classificação: JANELA rotulada (planejamento IoTEdu).
  classe=malicioso -> positivo real   |   classe=benigno -> negativo real
  IDS "detectou" a janela se contou >= 1 alerta naquela janela.

Para cada IDS (suricata, snort, zeek) e para a ORQUESTRAÇÃO (qualquer IDS):
  TP, FP, TN, FN, precisao, recall(sensibilidade/TPR), especificidade(TNR),
  F1, FPR, FNR, acuracia, acuracia_balanceada.

Foco do relatório: Falsos Negativos (ataques não detectados) e
Falsos Positivos (tráfego benigno que gerou alerta).

Uso: python3 metricas.py <execucoes.csv> <dir_saida>
Sem dependências externas (só stdlib).
"""
import csv, sys, os

def f(x):
    return f"{x:.3f}"

def metrics(tp, fp, tn, fn):
    P = tp + fn                      # positivos reais (maliciosos)
    N = tn + fp                      # negativos reais (benignos)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / P if P else 0.0      # sensibilidade / TPR / recall
    spec = tn / N if N else 0.0      # especificidade / TNR
    f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0.0
    fpr  = fp / N if N else 0.0      # taxa de falso positivo
    fnr  = fn / P if P else 0.0      # taxa de falso negativo
    acc  = (tp+tn)/(P+N) if (P+N) else 0.0
    bacc = (rec+spec)/2              # acurácia balanceada
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, precisao=prec, recall=rec,
                especificidade=spec, F1=f1, FPR=fpr, FNR=fnr,
                acuracia=acc, acuracia_balanceada=bacc)

def main():
    if len(sys.argv) < 3:
        print("uso: metricas.py <execucoes.csv> <dir_saida>"); sys.exit(2)
    csv_in, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    rows = list(csv.DictReader(open(csv_in, encoding="utf-8")))
    if not rows:
        print("execucoes.csv vazio"); sys.exit(1)

    subjects = ["suricata", "snort", "zeek", "orquestracao"]
    # aceita variações de nome de coluna (suricata | suricata_alertas, zeek | zeek_notices ...)
    aliases = {"suricata": ["suricata", "suricata_alertas"],
               "snort":    ["snort", "snort_alertas"],
               "zeek":     ["zeek", "zeek_notices", "zeek_alertas"]}
    def val(row, subj):
        for c in aliases[subj]:
            if c in row and row[c] not in (None, ""):
                return int(row[c] or 0)
        return 0
    def detected(row, subj):
        if subj == "orquestracao":
            return any(val(row, s) > 0 for s in ("suricata", "snort", "zeek"))
        return val(row, subj) > 0

    results = {}
    fn_list = {s: [] for s in subjects}   # ataques NÃO detectados (por cenário)
    fp_list = {s: [] for s in subjects}   # benignos que ALERTARAM
    for subj in subjects:
        tp = fp = tn = fn = 0
        for r in rows:
            malicioso = r["classe"].strip().lower().startswith("malic")
            det = detected(r, subj)
            if malicioso and det: tp += 1
            elif malicioso and not det:
                fn += 1; fn_list[subj].append(r["cenario"])
            elif (not malicioso) and det:
                fp += 1; fp_list[subj].append(r["cenario"])
            else: tn += 1
        results[subj] = metrics(tp, fp, tn, fn)

    # ---- metricas.csv ----
    cols = ["subject","TP","FP","TN","FN","precisao","recall","especificidade",
            "F1","FPR","FNR","acuracia","acuracia_balanceada"]
    with open(os.path.join(outdir, "metricas.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(cols)
        for subj in subjects:
            m = results[subj]
            w.writerow([subj]+[m["TP"],m["FP"],m["TN"],m["FN"]]+
                       [f(m[k]) for k in ["precisao","recall","especificidade","F1","FPR","FNR","acuracia","acuracia_balanceada"]])

    # ---- relatorio.md ----
    n_mal = sum(1 for r in rows if r["classe"].strip().lower().startswith("malic"))
    n_ben = sum(1 for r in rows if not r["classe"].strip().lower().startswith("malic"))
    L = []
    L.append("# Relatório de Eficácia de Detecção — IoTEdu\n")
    L.append(f"- Janelas avaliadas: **{len(rows)}** ({n_mal} maliciosas, {n_ben} benignas)")
    L.append(f"- Fonte: `{os.path.basename(csv_in)}`  |  unidade = janela rotulada\n")
    L.append("## Métricas por IDS e Orquestração\n")
    L.append("| Alvo | TP | FP | TN | FN | Precisão | Recall(Sens.) | Especif. | F1 | FPR | FNR | Acur.Bal. |")
    L.append("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    for subj in subjects:
        m = results[subj]
        L.append(f"| **{subj}** | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
                 f"{f(m['precisao'])} | {f(m['recall'])} | {f(m['especificidade'])} | {f(m['F1'])} | "
                 f"{f(m['FPR'])} | {f(m['FNR'])} | {f(m['acuracia_balanceada'])} |")
    L.append("")
    L.append("## Falsos Negativos (ataques NÃO detectados)\n")
    for subj in subjects:
        miss = fn_list[subj]
        if miss: L.append(f"- **{subj}**: {', '.join(miss)}")
        else:    L.append(f"- **{subj}**: nenhum ✅")
    L.append("")
    L.append("## Falsos Positivos (tráfego benigno que gerou alerta)\n")
    for subj in subjects:
        fps = fp_list[subj]
        if fps: L.append(f"- **{subj}**: {', '.join(fps)}")
        else:   L.append(f"- **{subj}**: nenhum ✅")
    L.append("")
    L.append("## Detecção por cenário (alertas por janela maliciosa)\n")
    L.append("| Cenário | Suricata | Snort | Zeek |")
    L.append("|---|--:|--:|--:|")
    for r in rows:
        if r["classe"].strip().lower().startswith("malic"):
            L.append(f"| {r['cenario']} | {val(r,'suricata')} | {val(r,'snort')} | {val(r,'zeek')} |")
    open(os.path.join(outdir, "relatorio.md"), "w", encoding="utf-8").write("\n".join(L)+"\n")

    # resumo no terminal
    print("\n=== RESUMO (eficácia) ===")
    print(f"{'alvo':14} {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3}  {'recall':>7} {'FPR':>6} {'FNR':>6} {'F1':>6}")
    for subj in subjects:
        m = results[subj]
        print(f"{subj:14} {m['TP']:>3} {m['FP']:>3} {m['TN']:>3} {m['FN']:>3}  "
              f"{f(m['recall']):>7} {f(m['FPR']):>6} {f(m['FNR']):>6} {f(m['F1']):>6}")
    print(f"\nGerado: {outdir}/metricas.csv e {outdir}/relatorio.md")

if __name__ == "__main__":
    main()
