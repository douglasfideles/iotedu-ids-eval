#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
graficos.py — gera as figuras (PNG) do relatório da campanha02 a partir dos CSVs
consolidados. Paleta categórica Okabe–Ito (segura para daltonismo); heatmap em
rampa sequencial de um só tom. Marcas limpas, grade recessiva, rótulos diretos.

Figuras (em <saida>/):
  metricas_por_ids.png       barras agrupadas: Recall/Precisão/F1 por IDS+orquestração
  rotulos_por_ids.png        barras empilhadas: TP/ERRO_CLASSIF/FN_PURO/FP/TN por IDS
  matriz_confusao.png        heatmap família intencionada × prevista (janelas malic.)
  deteccao_por_cenario.png   taxa de detecção (orquestração) por cenário + IC95
  erros_classificacao.png    contagem por par (família correta → prevista, IDS)

Uso: python3 graficos.py <consolidados_dir> <saida_dir>
Requer: matplotlib, numpy (stdlib + esses).
"""
import csv, sys, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict, Counter

# Okabe–Ito (CVD-safe)
OI = {"azul": "#0072B2", "laranja": "#E69F00", "verde": "#009E73", "ceu": "#56B4E9",
      "vermelho": "#D55E00", "roxo": "#CC79A7", "amarelo": "#F0E442", "preto": "#4D4D4D"}
INK = "#222222"; MUTED = "#6b6b6b"; GRID = "#e6e6e6"

def _style(ax):
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(MUTED); ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=INK, labelsize=9)
    ax.set_axisbelow(True); ax.yaxis.grid(True, color=GRID, lw=0.8); ax.xaxis.grid(False)

def read(path):
    return list(csv.DictReader(open(path, encoding="utf-8"))) if os.path.isfile(path) else []

def fnum(x, d=0.0):
    try: return float(x)
    except Exception: return d

# --------------------------------------------------------------------------
def g_metricas(cons, outdir):
    rows = {r["subject"]: r for r in read(os.path.join(cons, "metricas.csv"))}
    if not rows: return
    subs = [s for s in ["suricata", "snort", "zeek", "orquestracao"] if s in rows]
    mets = [("recall", "Recall", OI["azul"]), ("precisao", "Precisão", OI["laranja"]),
            ("F1", "F1", OI["verde"])]
    x = np.arange(len(subs)); w = 0.26
    fig, ax = plt.subplots(figsize=(7.2, 4.2), dpi=150)
    for i, (k, lab, c) in enumerate(mets):
        vals = [fnum(rows[s][k]) for s in subs]
        bars = ax.bar(x + (i-1)*w, vals, w, label=lab, color=c, edgecolor="white", linewidth=0.6)
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, v+0.015, f"{v:.2f}", ha="center", va="bottom",
                    fontsize=7.5, color=INK)
    ax.set_xticks(x); ax.set_xticklabels([s.capitalize() for s in subs])
    ax.set_ylim(0, 1.08); ax.set_ylabel("valor", color=INK)
    ax.set_title("Métricas de detecção por IDS (família-correta)", color=INK, fontsize=12, weight="bold")
    ax.legend(frameon=False, fontsize=8.5, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    _style(ax); fig.tight_layout()
    fig.savefig(os.path.join(outdir, "metricas_por_ids.png"), bbox_inches="tight"); plt.close(fig)

def g_rotulos(cons, outdir):
    det = read(os.path.join(cons, "classificacao_detalhe.csv"))
    if not det: return
    ids = ["suricata", "snort", "zeek"]
    cats = [("TP", OI["verde"]), ("ERRO_CLASSIF", OI["laranja"]),
            ("FN_PURO", OI["vermelho"]), ("FP", OI["roxo"]), ("TN", "#c9c9c9")]
    cnt = {i: Counter() for i in ids}
    for d in det:
        if d["ids"] in cnt: cnt[d["ids"]][d["rotulo"]] += 1
    fig, ax = plt.subplots(figsize=(7.2, 4.0), dpi=150)
    x = np.arange(len(ids)); bottom = np.zeros(len(ids))
    for rot, c in cats:
        vals = np.array([cnt[i].get(rot, 0) for i in ids], float)
        ax.bar(x, vals, 0.55, bottom=bottom, label=rot, color=c, edgecolor="white", linewidth=1.2)
        for xi, (v, b) in enumerate(zip(vals, bottom)):
            if v > 0: ax.text(xi, b+v/2, int(v), ha="center", va="center", fontsize=8,
                              color="white" if rot != "TN" else INK, weight="bold")
        bottom += vals
    ax.set_xticks(x); ax.set_xticklabels([i.capitalize() for i in ids])
    ax.set_ylabel("janelas", color=INK)
    ax.set_title("Rótulos por IDS (unidade = janela)", color=INK, fontsize=12, weight="bold")
    ax.legend(frameon=False, fontsize=8, ncol=5, loc="upper center", bbox_to_anchor=(0.5, -0.10))
    _style(ax); fig.tight_layout()
    fig.savefig(os.path.join(outdir, "rotulos_por_ids.png"), bbox_inches="tight"); plt.close(fig)

def g_matriz(cons, outdir):
    raw = list(csv.reader(open(os.path.join(cons, "matriz_confusao.csv"), encoding="utf-8"))) \
        if os.path.isfile(os.path.join(cons, "matriz_confusao.csv")) else []
    if len(raw) < 2: return
    cols = raw[0][1:]; rows = [r[0] for r in raw[1:]]
    M = np.array([[int(v) for v in r[1:]] for r in raw[1:]], float)
    fig, ax = plt.subplots(figsize=(max(6.5, 0.7*len(cols)+2.5), max(4.5, 0.5*len(rows)+2)), dpi=150)
    im = ax.imshow(M, cmap="Blues", aspect="auto")
    ax.set_xticks(range(len(cols))); ax.set_xticklabels(cols, rotation=40, ha="right", fontsize=8)
    ax.set_yticks(range(len(rows))); ax.set_yticklabels(rows, fontsize=8)
    mx = M.max() if M.size else 1
    for i in range(len(rows)):
        for j in range(len(cols)):
            v = int(M[i, j])
            if v: ax.text(j, i, v, ha="center", va="center", fontsize=8,
                          color="white" if M[i, j] > 0.55*mx else INK)
    ax.set_xlabel("família prevista (assinatura disparada)", color=INK, fontsize=9)
    ax.set_ylabel("família intencionada (ataque)", color=INK, fontsize=9)
    ax.set_title("Matriz de confusão — janelas maliciosas (3 IDS)", color=INK, fontsize=12, weight="bold")
    cb = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.03); cb.ax.tick_params(labelsize=8)
    for s in ax.spines.values(): s.set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "matriz_confusao.png"), bbox_inches="tight"); plt.close(fig)

def g_deteccao(cons, outdir):
    est = read(os.path.join(cons, "estatistica.csv"))
    orq = defaultdict(lambda: {"det": [], "lo": [], "hi": [], "n": 0})
    # usa a estatística por IDS não tem 'orquestracao'; então derivamos do detalhe
    det = read(os.path.join(cons, "classificacao_detalhe.csv"))
    if not det: return
    # taxa de detecção da ORQUESTRAÇÃO por cenário malicioso: janela detectada se
    # algum IDS = TP (família correta)
    by = defaultdict(lambda: {"tp": set(), "tot": set()})
    tp_win = defaultdict(set)
    win_cen = {}
    for d in det:
        if not d["classe"].startswith("malic"): continue
        w = d["execucao_id"]; win_cen[w] = d["cenario"]
        by[d["cenario"]]["tot"].add(w)
        if d["rotulo"] == "TP": by[d["cenario"]]["tp"].add(w)
    cens = sorted(by, key=lambda c: len(by[c]["tp"])/max(1, len(by[c]["tot"])))
    rate, lo, hi, labs = [], [], [], []
    for c in cens:
        tot = len(by[c]["tot"]); tp = len(by[c]["tp"]); p = tp/tot if tot else 0
        # Wilson 95
        z = 1.96; n = tot
        if n:
            d0 = 1+z*z/n; centro=(p+z*z/(2*n))/d0
            half=(z*((p*(1-p)/n+z*z/(4*n*n))**0.5))/d0
            l, h = max(0, centro-half), min(1, centro+half)
        else: l = h = 0
        rate.append(p); lo.append(p-l); hi.append(h-p); labs.append(f"{c}  (n={tot})")
    y = np.arange(len(cens))
    fig, ax = plt.subplots(figsize=(7.6, max(3.5, 0.45*len(cens)+1.5)), dpi=150)
    ax.barh(y, rate, color=OI["azul"], edgecolor="white", height=0.6,
            xerr=[lo, hi], error_kw=dict(ecolor=MUTED, elinewidth=1.2, capsize=3))
    for yi, r in zip(y, rate):
        ax.text(min(r+0.02, 0.98), yi, f"{r:.2f}", va="center", ha="left", fontsize=8, color=INK)
    ax.set_yticks(y); ax.set_yticklabels(labs, fontsize=8)
    ax.set_xlim(0, 1.12); ax.set_xlabel("taxa de detecção (orquestração) — IC 95% Wilson", color=INK)
    ax.set_title("Detecção por cenário de ataque", color=INK, fontsize=12, weight="bold")
    _style(ax); ax.xaxis.grid(True, color=GRID, lw=0.8); ax.yaxis.grid(False)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "deteccao_por_cenario.png"), bbox_inches="tight"); plt.close(fig)

def g_erros(cons, outdir):
    det = read(os.path.join(cons, "classificacao_detalhe.csv"))
    if not det: return
    pares = Counter()
    for d in det:
        if d["rotulo"] == "ERRO_CLASSIF":
            pares[f"{d['familia_intencionada']}→{d['familia_prevista']} ({d['ids']})"] += 1
    if not pares: return
    items = pares.most_common()
    labs = [k for k, _ in items][::-1]; vals = [v for _, v in items][::-1]
    y = np.arange(len(labs))
    fig, ax = plt.subplots(figsize=(7.6, max(2.5, 0.4*len(labs)+1.2)), dpi=150)
    ax.barh(y, vals, color=OI["laranja"], edgecolor="white", height=0.6)
    for yi, v in zip(y, vals):
        ax.text(v+0.05, yi, int(v), va="center", ha="left", fontsize=8, color=INK)
    ax.set_yticks(y); ax.set_yticklabels(labs, fontsize=8)
    ax.set_xlabel("janelas", color=INK)
    ax.set_title("Erros de classificação (ataque → assinatura de outra família)",
                 color=INK, fontsize=11.5, weight="bold")
    _style(ax); ax.xaxis.grid(True, color=GRID, lw=0.8); ax.yaxis.grid(False)
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "erros_classificacao.png"), bbox_inches="tight"); plt.close(fig)

def main():
    if len(sys.argv) < 3:
        print("uso: graficos.py <consolidados_dir> <saida_dir>"); sys.exit(2)
    cons, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    for fn in (g_metricas, g_rotulos, g_matriz, g_deteccao, g_erros):
        try: fn(cons, outdir)
        except Exception as e: print(f"[aviso] {fn.__name__}: {e}")
    pngs = sorted(f for f in os.listdir(outdir) if f.endswith(".png"))
    print(f"graficos gerados em {outdir}/: {', '.join(pngs) if pngs else '(nenhum)'}")

if __name__ == "__main__":
    main()
