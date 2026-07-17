# Pacote para o artigo — Campanha 02 (avaliação de IDS por interface)

Material pronto para incorporar ao artigo. Números extraídos do dataset completo
(240 janelas rotuladas, 15 repetições por cenário).

## Resumo dos resultados (rascunho de abstract)

Avaliou-se a eficácia de três IDS (Suricata, Snort e Zeek) e de sua orquestração
frente a **10 ataques** e **6 cenários de tráfego benigno**, gerados contra alvos
leves em uma interface de rede farejada (sem a aplicação sob teste). Foram
**240 janelas rotuladas** (150 maliciosas + 90 benignas), **6,88 h de captura** e
**~10,3 milhões de pacotes**. A **orquestração** dos três IDS alcançou recall
**0,813** (F1 0,871; acurácia balanceada 0,862), contra **0,673** do melhor IDS
isolado (Suricata) — ganho de **+0,140**. Suricata e Snort não produziram **nenhum
falso positivo** em 90 janelas benignas; os 8 FP observados foram todos do Zeek.
Além de acertos e erros de detecção, quantificou-se o **erro de classificação**
(detecção com assinatura de outra família): **57 janelas**, com padrões
recorrentes (`sqli→xss`, `path-traversal→dos-http`). Dois ataques não tiveram
cobertura efetiva (`ssh-bruteforce`, `port-scanner-tcp`), com causa-raiz
identificada nas regras.

## Números-chave

- Janelas: **240** (150 maliciosas, 90 benignas) · Captura: **6,88 h** · Pacotes: **10.288.250**
- Recall: Suricata **0,673** · Snort **0,460** · Zeek **0,400** · **Orquestração 0,813**
- Falsos positivos: Suricata **0** · Snort **0** · Zeek **8** (todos em tráfego benigno)
- Erros de classificação: **57 janelas** (matriz de confusão multiclasse)
- Ganho da orquestração: **+0,140** de recall sobre o melhor IDS isolado

## Principais achados (com causa-raiz)

| Achado | Evidência | Causa-raiz |
|---|---|---|
| SSH brute-force não detectado | 44/45 janelas FN | Regras vigiam porta **2222** (publicada no host); alvo escuta **22** (nativa do container) → nenhuma casa |
| Port scan TCP mal coberto | 34/45 janelas FN | Sem assinatura dedicada de *port scan* por conexão TCP |
| `sqli → xss` (erro de classif., Snort) | 15 janelas | Regra XSS de alta-frequência dispara com `content:"<"` + taxa — payloads do sqlmap contêm `<` |
| `path-traversal → dos-http` (erro de classif.) | 30 janelas | Fuzzing do ffuf em alta taxa cruza limiares de DoS HTTP |
| Falsos positivos do Zeek | 8 janelas benignas | Limiares de Scan/ICMP sensíveis a curl/nping legítimos |

## Recomendações de ajuste de regras

1. Apontar `brute-force-ssh`/`telnet` para as portas nativas (`22`/`23`) — ou atacar as portas publicadas.
2. Exigir token XSS real (`<script`, `onerror=`) na regra de XSS de alta-frequência, não `<` isolado.
3. Priorizar assinaturas de conteúdo de path-traversal e elevar limiares de DoS HTTP.
4. Adicionar regra dedicada de *port scan* (SYNs a múltiplas portas por origem).
5. Elevar limiares das políticas de Scan/ICMP do Zeek para reduzir FP.
6. DNS tunneling: reduzir limiar de taxa + checagem de entropia/comprimento.

## Arquivos deste pacote

- `tabela_metricas.tex` — Tabela 1 (métricas por IDS), booktabs, pronta para `\input{}`.
- `tabela_confusao.tex` — Tabela 2 (matriz de confusão), booktabs.
- `figuras/` — 5 figuras (PNG, 150 dpi, paleta segura para daltonismo):
  - `metricas_por_ids.png` — barras de Recall/Precisão/F1 por IDS.
  - `rotulos_por_ids.png` — empilhado TP/erro-classif/FN/FP/TN por IDS.
  - `matriz_confusao.png` — heatmap intencionada × prevista.
  - `deteccao_por_cenario.png` — detecção por ataque com IC 95%.
  - `erros_classificacao.png` — contagem por par de erro de classificação.

Relatório completo (metodologia, topologia, estatística com IC 95%, discussão por RQ):
`../RELATORIO.md`. Dados brutos: `../consolidados/*.csv`. Reprodutibilidade:
`../regras/hashes.txt`.
