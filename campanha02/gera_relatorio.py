#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gera_relatorio.py — monta o RELATORIO.md da campanha02 a partir dos consolidados.

Reúne: horas de captura por classe, nº de pacotes, tipos de tráfego, métricas
binárias (metricas.csv), estatística por cenário com IC95 (estatistica.csv),
matriz de confusão multiclasse, tabela de erros de classificação e lista de FP.

Uso: python3 gera_relatorio.py <janelas.csv> <consolidados_dir> <saida.md>
Sem dependências externas.
"""
import csv, sys, os
from datetime import datetime
from collections import defaultdict

def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None

def read_csv(path):
    return list(csv.DictReader(open(path, encoding="utf-8"))) if os.path.isfile(path) else []

def main():
    if len(sys.argv) < 4:
        print("uso: gera_relatorio.py <janelas.csv> <consolidados_dir> <saida.md>"); sys.exit(2)
    janelas_csv, cons, saida = sys.argv[1:4]
    janelas = read_csv(janelas_csv)
    metricas = read_csv(os.path.join(cons, "metricas.csv"))
    estat = read_csv(os.path.join(cons, "estatistica.csv"))
    detalhe = read_csv(os.path.join(cons, "classificacao_detalhe.csv"))

    # ---- horas, pacotes, tipos de tráfego ----
    seg = defaultdict(float); pkts = defaultdict(int)
    n_por_classe = defaultdict(int)
    cen_mal = set(); cen_ben = set(); reps = defaultdict(int)
    for w in janelas:
        classe = "malicioso" if w["classe"].strip().lower().startswith("malic") else "benigno"
        n_por_classe[classe] += 1
        reps[(w["cenario"], classe)] += 1
        t0, t1 = parse_ts(w.get("t_start")), parse_ts(w.get("t_end"))
        if t0 and t1:
            seg[classe] += max(0.0, (t1 - t0).total_seconds())
        try:
            pkts[classe] += int(w.get("pcap_pacotes", 0) or 0)
        except ValueError:
            pass
        (cen_mal if classe == "malicioso" else cen_ben).add(w["cenario"])
    horas = {k: v/3600.0 for k, v in seg.items()}
    tot_h = sum(horas.values()); tot_p = sum(pkts.values())

    L = []
    L.append("# Relatório — Campanha 02 (avaliação de IDS por interface de rede)\n")
    L.append("Ataques gerados a partir de `sbcup2026-ataques` contra alvos leves numa rede "
             "docker farejada pelos 3 IDS (Suricata, Snort, Zeek). **Sem a aplicação IoTEdu** "
             "— avaliação de como as regras se comportam diante do tráfego capturado.\n")

    # ---- 0. Metodologia / detalhes do experimento (estático) ----
    L.append("## 0. Metodologia e detalhes do experimento\n")
    L.append("**Objetivo.** Medir a eficácia de detecção dos IDS (e da orquestração dos três) "
             "frente a tráfego malicioso e benigno numa interface de rede, avaliando também "
             "falsos positivos e **erros de classificação** (detecção com assinatura de família errada).\n")
    L.append("**Topologia.** Rede docker dedicada `ids-eval-net` (172.30.0.0/24) farejada pela "
             "bridge `br-<netid>`. Na mesma rede: alvos leves (HTTP `172.30.0.5:80`, SSH "
             "`172.30.0.6:22`), o atacante (`172.30.0.10`), o gerador benigno (`172.30.0.20`) e "
             "um IP de *flush* descartável (`172.30.0.250`, nunca contado). Os IDS rodam em "
             "`network_mode: host` (Suricata/Snort/Zeek do `mvpv1-snapshot`), recriados com "
             "`--force-recreate` (nunca `restart`). **A aplicação IoTEdu (back/front) não é usada.**\n")
    L.append("**Unidade de análise.** A *janela rotulada*: uma execução isolada de UM cenário "
             "(malicioso ou benigno), sem tráfego concorrente. Por janela salvam-se as fatias de "
             "alertas de cada IDS (por *byte-offset* + filtro de *timestamp*, que remove notices do "
             "Zeek escritos em lote e evita vazamento entre janelas), o PCAP, o stdout do gerador e um manifesto.\n")
    L.append("**Os 10 ataques (família intencionada e alvo):**\n")
    L.append("| # | Ataque (sbcup26) | Família | Alvo |")
    L.append("|--:|---|---|---|")
    L.append("| 1 | icmp-flood | flood-icmp | 172.30.0.5 |")
    L.append("| 2 | syn-flood | flood-syn | 172.30.0.5:80 |")
    L.append("| 3 | udp-flood | flood-udp | 172.30.0.5:80 |")
    L.append("| 4 | dos-http-simple | dos-http | 172.30.0.5:80 |")
    L.append("| 5 | sql-injection | sqli | 172.30.0.5:80 |")
    L.append("| 6 | xss-scanner | xss | 172.30.0.5:80 |")
    L.append("| 7 | idor-path-traversal | path-traversal | 172.30.0.5:80 |")
    L.append("| 8 | port-scanner-tcp | scan | 172.30.0.5 |")
    L.append("| 9 | ssh-bruteforce | ssh-brute | 172.30.0.6:22 |")
    L.append("| 10 | dns-tunneling | dns-tunneling | resolvers públicos |")
    L.append("")
    L.append("**Os 6 cenários de tráfego benigno (avaliação de falsos positivos):**\n")
    L.append("| Benigno | Tráfego legítimo |")
    L.append("|---|---|")
    L.append("| benigno-icmp | ping em baixa taxa |")
    L.append("| benigno-http | GETs HTTP normais |")
    L.append("| benigno-dns | consultas DNS legítimas |")
    L.append("| benigno-ssh | conexões SSH pontuais |")
    L.append("| benigno-scan | acesso normal a 1 serviço |")
    L.append("| benigno-mix | HTTP+DNS+ICMP+SSH leves |")
    L.append("")
    L.append("**Classificação por janela e IDS.** `TP` = ≥1 alerta da família correta; "
             "`FN_PURO` = nenhum alerta de ataque; `ERRO_CLASSIF` = detectou, mas só com "
             "assinatura de **outra** família (nem TP, nem FN puro); `FP` = janela benigna com "
             "qualquer alerta de ataque; `TN` = benigna sem alerta. A rajada de *flush* e alertas "
             "fora do intervalo da janela são descartados.\n")
    L.append("**Métricas.** Precisão, Recall (sensibilidade), Especificidade, F1, FPR, FNR, "
             "acurácia balanceada — por IDS e para a **orquestração** (detecta se qualquer IDS "
             "detecta). Denominador zero ⇒ métrica indefinida (nunca forçada a 0). As repetições "
             "são agregadas com **intervalo de confiança de Wilson 95%**.\n")
    L.append("## 1. Resumo da captura\n")
    L.append(f"- **Janelas avaliadas:** {len(janelas)} "
             f"({n_por_classe['malicioso']} maliciosas, {n_por_classe['benigno']} benignas)")
    L.append(f"- **Horas de captura (total):** {tot_h:.2f} h  "
             f"(maliciosa: {horas.get('malicioso',0):.2f} h · benigna: {horas.get('benigno',0):.2f} h)")
    L.append(f"- **Pacotes capturados (total):** {tot_p:,} "
             f"(maliciosa: {pkts.get('malicioso',0):,} · benigna: {pkts.get('benigno',0):,})")
    L.append(f"- **Tipos de tráfego malicioso ({len(cen_mal)}):** {', '.join(sorted(cen_mal)) or '—'}")
    L.append(f"- **Tipos de tráfego benigno ({len(cen_ben)}):** {', '.join(sorted(cen_ben)) or '—'}\n")

    L.append("### Janelas e horas por cenário\n")
    L.append("| Cenário | Classe | Repetições | Horas | Pacotes |")
    L.append("|---|---|--:|--:|--:|")
    ch_seg = defaultdict(float); ch_pk = defaultdict(int)
    for w in janelas:
        classe = "malicioso" if w["classe"].strip().lower().startswith("malic") else "benigno"
        t0, t1 = parse_ts(w.get("t_start")), parse_ts(w.get("t_end"))
        if t0 and t1:
            ch_seg[(w["cenario"], classe)] += max(0.0, (t1-t0).total_seconds())
        try:
            ch_pk[(w["cenario"], classe)] += int(w.get("pcap_pacotes", 0) or 0)
        except ValueError:
            pass
    for (cen, classe) in sorted(reps):
        L.append(f"| {cen} | {classe} | {reps[(cen,classe)]} | "
                 f"{ch_seg[(cen,classe)]/3600.0:.2f} | {ch_pk[(cen,classe)]:,} |")
    L.append("")

    # ---- métricas binárias por IDS ----
    if metricas:
        L.append("## 2. Métricas de detecção (família-correta) por IDS\n")
        L.append("> Detecção = ≥1 alerta com assinatura da **família correta**. "
                 "Alertas de família errada NÃO contam como TP (ver §4).\n")
        L.append("| Alvo | TP | FP | TN | FN | Precisão | Recall | Especif. | F1 | FPR | Acur.Bal. |")
        L.append("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
        for m in metricas:
            L.append(f"| **{m['subject']}** | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
                     f"{m['precisao']} | {m['recall']} | {m['especificidade']} | {m['F1']} | "
                     f"{m['FPR']} | {m['acuracia_balanceada']} |")
        L.append("")
        L.append("![Métricas de detecção por IDS](graficos/metricas_por_ids.png)\n")
        L.append("![Rótulos por IDS (TP/erro-classif/FN/FP/TN)](graficos/rotulos_por_ids.png)\n")

    # ---- estatística por cenário (IC95) ----
    if estat:
        L.append("## 3. Estatística por cenário e IDS (repetições, IC 95% de Wilson)\n")
        L.append("| Cenário | Classe | IDS | n | Taxa detec. | IC95 | Erro classif. | FN puro | FP |")
        L.append("|---|---|---|--:|--:|:--:|--:|--:|--:|")
        for r in estat:
            ic = (f"[{r['det_ic95_low']}, {r['det_ic95_high']}]"
                  if r.get("det_ic95_low") else "—")
            L.append(f"| {r['cenario']} | {r['classe']} | {r['ids']} | {r['n']} | "
                     f"{r.get('taxa_det') or '—'} | {ic} | {r.get('taxa_erro_classif') or '—'} | "
                     f"{r.get('taxa_fn_puro') or '—'} | {r.get('taxa_fp') or '—'} |")
        L.append("")
        L.append("![Taxa de detecção por cenário (orquestração, IC 95%)](graficos/deteccao_por_cenario.png)\n")

    # ---- erros de classificação (o ponto central pedido) ----
    L.append("## 4. Erros de classificação (detecção com assinatura errada)\n")
    L.append("Casos em que o IDS **detectou** o ataque mas atribuiu assinatura de **outra "
             "família** (ex.: flood classificado como SQLi). Não é falso negativo (houve "
             "detecção) nem falso positivo. Tratado como categoria própria.\n")
    L.append("![Matriz de confusão (intencionada × prevista)](graficos/matriz_confusao.png)\n")
    L.append("![Erros de classificação por par](graficos/erros_classificacao.png)\n")
    erros = [d for d in detalhe if d["rotulo"] == "ERRO_CLASSIF"]
    if erros:
        L.append("| Cenário | IDS | Família correta | Classificada como | Janela |")
        L.append("|---|---|---|---|---|")
        for d in erros:
            L.append(f"| {d['cenario']} | {d['ids']} | {d['familia_intencionada']} | "
                     f"{d['familia_prevista']} | {d['execucao_id']} |")
    else:
        L.append("Nenhum erro de classificação observado. ✅")
    L.append("")
    mc = os.path.join(cons, "matriz_confusao.csv")
    if os.path.isfile(mc):
        rows = read_csv(mc)
        # matriz_confusao.csv tem cabeçalho especial (1ª col = 'intencionada\prevista')
        raw = list(csv.reader(open(mc, encoding="utf-8")))
        if raw:
            L.append("### Matriz de confusão (família intencionada × prevista, janelas maliciosas)\n")
            L.append("| " + " | ".join(raw[0]) + " |")
            L.append("|" + "|".join(["---"]*len(raw[0])) + "|")
            for r in raw[1:]:
                L.append("| " + " | ".join(r) + " |")
            L.append("")

    # ---- falsos positivos (regras responsáveis) ----
    L.append("## 5. Falsos positivos no tráfego benigno\n")
    fps = [d for d in detalhe if d["rotulo"] == "FP"]
    if fps:
        L.append("| Cenário benigno | IDS | Família(s) alertada(s) | Janela |")
        L.append("|---|---|---|---|")
        for d in fps:
            L.append(f"| {d['cenario']} | {d['ids']} | {d['familia_prevista']} | {d['execucao_id']} |")
    else:
        L.append("Nenhum falso positivo observado no tráfego benigno. ✅")
    L.append("")

    # ---- 6. Síntese por questão de pesquisa (data-driven) ----
    L.append("## 6. Síntese por questão de pesquisa\n")
    mby = {m["subject"]: m for m in metricas} if metricas else {}
    def rec(s): return mby.get(s, {}).get("recall", "—")
    def fp(s):  return mby.get(s, {}).get("FP", "—")
    L.append(f"- **RQ1 — Eficácia por IDS.** Recall (detecção família-correta): "
             f"Suricata {rec('suricata')}, Snort {rec('snort')}, Zeek {rec('zeek')}; "
             f"orquestração {rec('orquestracao')}.")
    # RQ2: cenários maliciosos com FN em TODOS os IDS
    mal = [d for d in detalhe if d["classe"].startswith("malic")]
    cen_ids = defaultdict(set)
    for d in mal:
        if d["rotulo"] in ("FN_PURO",):
            cen_ids[d["cenario"]].add(d["ids"])
    tot_ids = len({d["ids"] for d in detalhe}) or 3
    piores = sorted([c for c, s in cen_ids.items() if len(s) >= tot_ids])
    L.append(f"- **RQ2 — Piores falsos negativos.** Cenários não detectados por nenhum IDS "
             f"(sem cobertura efetiva): {', '.join(piores) if piores else 'nenhum'}.")
    # RQ3: FP
    total_fp = sum(1 for d in detalhe if d["rotulo"] == "FP")
    ben_fp = sorted({d["cenario"] for d in detalhe if d["rotulo"] == "FP"})
    L.append(f"- **RQ3 — Falsos positivos (tráfego benigno).** {total_fp} janela(s) benigna(s) "
             f"com alerta indevido"
             + (f" (cenários: {', '.join(ben_fp)}). " if ben_fp else ". ")
             + f"FP por IDS: Suricata {fp('suricata')}, Snort {fp('snort')}, Zeek {fp('zeek')}.")
    # RQ4: ganho da orquestração
    try:
        best = max(float(mby[s]["recall"]) for s in ("suricata","snort","zeek") if s in mby)
        orq = float(mby["orquestracao"]["recall"])
        L.append(f"- **RQ4 — Orquestração.** Recall combinado {orq:.3f} vs. melhor IDS isolado "
                 f"{best:.3f} → ganho de {orq-best:+.3f}. Combinar os três "
                 f"{'aumenta' if orq>best else 'não aumenta'} a cobertura.")
    except Exception:
        L.append("- **RQ4 — Orquestração.** (métricas insuficientes)")
    # RQ5: erros de classificação
    n_err = sum(1 for d in detalhe if d["rotulo"] == "ERRO_CLASSIF")
    pares = sorted({f"{d['familia_intencionada']}→{d['familia_prevista']} ({d['ids']})"
                    for d in detalhe if d["rotulo"] == "ERRO_CLASSIF"})
    L.append(f"- **RQ5 — Regras problemáticas / erro de classificação.** {n_err} janela(s) com "
             f"detecção de família errada. Pares observados: "
             f"{'; '.join(pares) if pares else 'nenhum'}. Ver §4 e a matriz de confusão.")
    L.append("")
    L.append("---")
    L.append("_Gerado por gera_relatorio.py (campanha02)._")
    open(saida, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"RELATORIO gravado: {saida}")
    print(f"  horas total={tot_h:.2f}  pacotes total={tot_p}  janelas={len(janelas)}")

if __name__ == "__main__":
    main()
