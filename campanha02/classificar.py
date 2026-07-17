#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
classificar.py — classificação por FAMÍLIA dos alertas de cada janela e separação
de TP / FN puro / ERRO DE CLASSIFICAÇÃO / FP / TN (campanha02, avaliação por interface).

A unidade é a JANELA rotulada (uma execução de ataque OU de tráfego benigno). Para
cada janela e cada IDS (suricata, snort, zeek) lê a FATIA de alertas capturada e,
via mapa-assinaturas.yaml, decide a família de cada alerta pelo texto `msg`.

Rótulo por (janela, IDS):
  malicioso: n_corretos>0            -> TP
             n_corretos=0, n_errados>0 -> ERRO_CLASSIF (detectou, assinatura de
                                          outra família — nem TP, nem FN puro)
             n_corretos=0, n_errados=0 -> FN_PURO (nenhum alerta de ataque)
  benigno:   qualquer alerta de ataque -> FP   ;  senão -> TN

Saídas (em <outdir>):
  execucoes.csv           -> p/ metricas.py (contagens = corretos no malicioso,
                             alertas-de-ataque no benigno). Detecção binária estrita.
  classificacao_detalhe.csv -> uma linha por (janela, IDS) com o rótulo e famílias.
  matriz_confusao.csv     -> família intencionada x família detectada (janelas malic.)
  classificacao.md        -> resumo legível (contagens, tabela de erros de classificação)

Uso: python3 classificar.py <janelas.csv> <dir_execucoes> <mapa.yaml> <dir_saida>
Requer: PyYAML (só p/ ler o mapa).
"""
import csv, sys, os, json, re
from datetime import datetime, timezone
import yaml

IDS = ["suricata", "snort", "zeek"]
# margem (s) de tolerância de relógio ao atribuir alertas por timestamp à janela.
# Zeek escreve notices em lote (atrasado) -> um flood pode "vazar" para janelas
# seguintes na fatia por offset; o ts real do alerta os desmascara e exclui.
TS_MARGIN = 5.0

def to_epoch(s):
    """ISO (…Z / +00:00) -> epoch float, ou None."""
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        try:
            return datetime.strptime(s[:26], "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
        except Exception:
            return None

def carregar_mapa(path):
    m = yaml.safe_load(open(path, encoding="utf-8"))
    ignorar = [p.lower() for p in m.get("ignorar_prefixos", [])]
    ordem = m["ordem"]
    # compila padrões por família, na ordem de precedência
    compilados = [(fam, [re.compile(p, re.IGNORECASE) for p in m["familias"][fam]["padroes"]])
                  for fam in ordem]
    cenarios = m["cenarios"]
    return ignorar, compilados, cenarios, set(ordem)

def familia_do_msg(msg, ignorar, compilados):
    """Retorna a família do alerta pelo texto do msg, ou None se não for ataque/for ignorado."""
    if not msg:
        return None
    low = msg.strip().lower()
    for pre in ignorar:
        if low.startswith(pre):
            return None
    for fam, regexes in compilados:
        for rx in regexes:
            if rx.search(msg):
                return fam
    return "nao-mapeado"   # alerta que não é logging, mas não casou família conhecida

# --- parsers das fatias por IDS: devolvem lista de (msg, src_ip, ts_epoch|None) ---
def parse_suricata(path):
    out = []
    if not os.path.isfile(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("event_type") != "alert":
            continue
        sig = (o.get("alert") or {}).get("signature", "")
        src = o.get("src_ip", "")
        out.append((sig, src, to_epoch(o.get("timestamp"))))
    return out

_SNORT_MSG = re.compile(r'\[\*\*\]\s*(?:\[\d+:\d+:\d+\]\s*)?"?([^"\[]+?)"?\s*\[\*\*\]')
_IP = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
def parse_snort(path):
    out = []
    if not os.path.isfile(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if "[**]" not in line:
            continue
        mm = _SNORT_MSG.search(line)
        msg = mm.group(1).strip() if mm else ""
        # último IP da linha costuma ser o destino; primeiro, a origem
        ips = _IP.findall(line)
        src = ips[0] if ips else ""
        # Snort alert_fast: "MM/DD-HH:MM:SS.us" (sem ano) -> ts pouco confiável;
        # mantém None e confia na fatia por offset (writes do Snort são prontos).
        out.append((msg, src, None))
    return out

def parse_zeek(path):
    out = []
    if not os.path.isfile(path):
        return out
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # tenta JSON (notices.jsonl); senão TSV do notice.log
        msg = src = ""; ts = None
        if line.startswith("{"):
            try:
                o = json.loads(line)
                msg = "%s %s" % (o.get("note", ""), o.get("msg", ""))
                src = o.get("src", "") or o.get("id.orig_h", "")
                ts = float(o["ts"]) if o.get("ts") not in (None, "") else None
            except Exception:
                continue
        else:
            cols = line.split("\t")
            # notice.log padrão: ts uid id.orig_h id.orig_p id.resp_h ... note msg ...
            src = cols[2] if len(cols) > 2 else ""
            msg = " ".join(cols[9:12]) if len(cols) > 11 else " ".join(cols)
            try:
                ts = float(cols[0])
            except Exception:
                ts = None
        out.append((msg, src, ts))
    return out

PARSERS = {"suricata": parse_suricata, "snort": parse_snort, "zeek": parse_zeek}
SLICE_FILE = {"suricata": "suricata.jsonl", "snort": "snort.txt", "zeek": "zeek.txt"}

def main():
    if len(sys.argv) < 5:
        print("uso: classificar.py <janelas.csv> <dir_execucoes> <mapa.yaml> <dir_saida>")
        sys.exit(2)
    janelas_csv, dir_exec, mapa_path, outdir = sys.argv[1:5]
    os.makedirs(outdir, exist_ok=True)
    ignorar, compilados, cenarios, familias_validas = carregar_mapa(mapa_path)

    janelas = list(csv.DictReader(open(janelas_csv, encoding="utf-8")))
    if not janelas:
        print("janelas.csv vazio"); sys.exit(1)

    detalhe = []          # por (janela, IDS)
    exec_rows = []        # p/ metricas.py (por janela)
    # matriz[intencionada][detectada] = contagem de janelas (por IDS, agregada)
    matriz = {}
    erros_classif = []    # lista de (cenario, ids, intencionada, detectada, execucao_id)

    for w in janelas:
        wid = w["execucao_id"]; cen = w["cenario"]
        classe = w["classe"].strip().lower()
        malic = classe.startswith("malic")
        intended = w.get("familia_intencionada") or cenarios.get(cen, "?")
        flush_ip = (w.get("flush_ip") or "").strip()
        win_ini = to_epoch(w.get("t_start")); win_fim = to_epoch(w.get("t_end"))
        row_counts = {"suricata": 0, "snort": 0, "zeek": 0}

        for ids in IDS:
            slc = os.path.join(dir_exec, wid, SLICE_FILE[ids])
            alerts = PARSERS[ids](slc)
            # exclui a rajada de flush (IP descartável) da contagem
            if flush_ip:
                alerts = [(m, s, t) for (m, s, t) in alerts if flush_ip not in (s or "")]
            # atribui por TIMESTAMP: descarta alertas cujo ts cai fora da janela
            # (Zeek escreve em lote -> floods "vazam" para janelas seguintes).
            if win_ini is not None and win_fim is not None:
                alerts = [(m, s, t) for (m, s, t) in alerts
                          if t is None or (win_ini - TS_MARGIN) <= t <= (win_fim + TS_MARGIN)]
            fams = [familia_do_msg(m, ignorar, compilados) for (m, s, t) in alerts]
            fams = [f for f in fams if f is not None]          # remove LOG/TESTE
            ataque_alertas = [f for f in fams if f in familias_validas]  # famílias reais
            n_total = len(fams)
            n_correto = sum(1 for f in fams if f == intended)
            n_errado = sum(1 for f in ataque_alertas if f != intended)

            if malic:
                row_counts[ids] = n_correto
                if n_correto > 0:
                    rotulo = "TP"; pred = intended
                elif len(ataque_alertas) > 0:
                    rotulo = "ERRO_CLASSIF"
                    # família prevista = a de ataque mais frequente
                    pred = max(set(ataque_alertas), key=ataque_alertas.count)
                    erros_classif.append((cen, ids, intended, pred, wid))
                else:
                    rotulo = "FN_PURO"; pred = "NENHUM"
                matriz.setdefault(intended, {}).setdefault(pred, 0)
                matriz[intended][pred] += 1
            else:
                # benigno: qualquer alerta de ataque (qualquer família) é FP
                row_counts[ids] = len(ataque_alertas)
                rotulo = "FP" if len(ataque_alertas) > 0 else "TN"
                pred = ",".join(sorted(set(ataque_alertas))) if ataque_alertas else "-"

            detalhe.append(dict(
                execucao_id=wid, cenario=cen, familia_intencionada=intended,
                classe=("malicioso" if malic else "benigno"), ids=ids,
                n_alertas=n_total, n_corretos=n_correto, n_errados=n_errado,
                familias_detectadas=";".join(sorted(set(fams))) if fams else "-",
                rotulo=rotulo, familia_prevista=pred))

        exec_rows.append(dict(
            execucao_id=wid, cenario=cen, familia=intended,
            classe=("malicioso" if malic else "benigno"),
            attacker_ip=w.get("attacker_ip", ""), t_start=w.get("t_start", ""),
            t_end=w.get("t_end", ""), suricata=row_counts["suricata"],
            snort=row_counts["snort"], zeek=row_counts["zeek"],
            pcap_pacotes=w.get("pcap_pacotes", 0)))

    # ---- execucoes.csv (compatível com metricas.py) ----
    cols = ["execucao_id","cenario","familia","classe","attacker_ip","t_start","t_end",
            "suricata","snort","zeek","pcap_pacotes"]
    with open(os.path.join(outdir, "execucoes.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols); w.writeheader(); w.writerows(exec_rows)

    # ---- classificacao_detalhe.csv ----
    dcols = ["execucao_id","cenario","familia_intencionada","classe","ids","n_alertas",
             "n_corretos","n_errados","familias_detectadas","rotulo","familia_prevista"]
    with open(os.path.join(outdir, "classificacao_detalhe.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=dcols); w.writeheader(); w.writerows(detalhe)

    # ---- matriz_confusao.csv (intencionada x prevista, janelas maliciosas, todos IDS) ----
    preds = sorted({p for d in matriz.values() for p in d})
    with open(os.path.join(outdir, "matriz_confusao.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh); w.writerow(["intencionada\\prevista"] + preds)
        for intended in sorted(matriz):
            w.writerow([intended] + [matriz[intended].get(p, 0) for p in preds])

    # ---- resumo por IDS ----
    def cont(ids, rot):
        return sum(1 for d in detalhe if d["ids"] == ids and d["rotulo"] == rot)
    L = ["# Classificação por família — campanha02\n"]
    nmal = sum(1 for w in janelas if w["classe"].strip().lower().startswith("malic"))
    nben = len(janelas) - nmal
    L.append(f"- Janelas: **{len(janelas)}** ({nmal} maliciosas, {nben} benignas)\n")
    L.append("## Rótulos por IDS (unidade = janela)\n")
    L.append("| IDS | TP | ERRO_CLASSIF | FN_PURO | FP | TN |")
    L.append("|---|--:|--:|--:|--:|--:|")
    for ids in IDS:
        L.append(f"| **{ids}** | {cont(ids,'TP')} | {cont(ids,'ERRO_CLASSIF')} | "
                 f"{cont(ids,'FN_PURO')} | {cont(ids,'FP')} | {cont(ids,'TN')} |")
    L.append("\n> **ERRO_CLASSIF** = houve detecção, mas com assinatura de OUTRA família "
             "(nem falso negativo puro, nem falso positivo). Ver matriz de confusão.\n")
    if erros_classif:
        L.append("## Erros de classificação (ataque real → assinatura disparada)\n")
        L.append("| Cenário | IDS | Família correta | Classificada como | Janela |")
        L.append("|---|---|---|---|---|")
        for cen, ids, inten, pred, wid in erros_classif:
            L.append(f"| {cen} | {ids} | {inten} | {pred} | {wid} |")
    else:
        L.append("## Erros de classificação\n\nNenhum. ✅")
    open(os.path.join(outdir, "classificacao.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")

    # terminal
    print("=== classificar.py ===")
    print(f"janelas={len(janelas)}  maliciosas={nmal}  benignas={nben}")
    for ids in IDS:
        print(f"  {ids:9} TP={cont(ids,'TP'):3} ERRO_CLASSIF={cont(ids,'ERRO_CLASSIF'):3} "
              f"FN_PURO={cont(ids,'FN_PURO'):3} FP={cont(ids,'FP'):3} TN={cont(ids,'TN'):3}")
    print(f"Saídas em {outdir}/ (execucoes.csv, classificacao_detalhe.csv, matriz_confusao.csv, classificacao.md)")

if __name__ == "__main__":
    main()
