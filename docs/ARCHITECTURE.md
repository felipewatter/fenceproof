# Arquitetura — FenceProof

## 1. Objetivo e fronteiras

O FenceProof implementa raciocínio simbólico **offline** sobre uma linguagem própria e deliberadamente limitada de ACLs de camada 3/4. Ele **não** tenta importar integralmente políticas de fabricantes, nem interpreta regras NAT, regras por estado, DPI, FQDN, identidade, horário ou interface. A exatidão referida nesta documentação aplica-se **apenas a esse modelo**.

Arquitetura:

```text
Arquivo JSON (limite 1 MiB)
       │
       ▼
 parser.py ── validação estrita, CIDR canônico, portas normalizadas
       │
       ▼
 model.py ─── Policy → Rule → Box(family, protocol, src, dst, port)
       │
       ▼
 engine.py ── decomposição exata de hiper-retângulos disjuntos
       │               ├── check: shadowing + assertions + sinais de risco
       │               └── diff: diferença de conjuntos de tráfego permitido
       ▼
 report.py ── texto / JSON / SARIF 2.1.0
       │
       ▼
 cli.py ───── códigos de saída e SHA-256 do input
```

## 2. Semântica formal do pacote

Um fluxo é `(family, source, destination, protocol, destination_port)`.

- `family` ∈ {IPv4, IPv6}; origem e destino devem ter a mesma família.
- `protocol` ∈ {TCP, UDP, ICMP}; a regra `any` é expandida para os três. **Outros protocolos não existem neste modelo**.
- `destination_port` ∈ [1,65535] para TCP/UDP; o ICMP usa a sentinela de porta `0` apenas internamente.
- Endereços e portas são inteiros em intervalos fechados.
- Regras são avaliadas na ordem do arquivo: **a primeira correspondência determina a decisão** (`allow`/`deny`). Na ausência de regra, usa-se `default_action`.
- O avaliador é stateless; cada fluxo é independente. Não há lógica de conexão estabelecida, NAT ou direcionalidade implícita.

## 3. Modelo de região e prova de completude

Para uma família IP e protocolo fixos, uma regra corresponde ao produto cartesiano de três intervalos: `S × D × P` (origem × destino × porta).

A rotina `Box.subtract(A, B)` calcula `A \ B` de forma **exata e sem sobreposição**. Em cada dimensão, preserva os fragmentos abaixo e acima da interseção e restringe o centro à interseção antes de avançar à próxima dimensão. O resultado tem no máximo seis caixas para cada subtração de uma caixa por outra.

Para cada regra `R[i]`, o motor calcula os fragmentos ainda não capturados por `R[0..i-1]`. Fragmentos restantes representam tráfego efetivamente decidido pela regra atual; vazio significa regra completamente encoberta; volume parcial indica regra parcialmente encoberta.

O `diff` calcula o conjunto de **fluxos efetivamente permitidos** em cada política, incluindo o complemento das regras quando o default é `allow`. Depois subtrai os conjuntos de caixas da outra política. Se a diferença `Allowed(A) \ Allowed(B)` não está vazia, há tráfego que passou a ser negado; o inverso mostra tráfego recém-permitido. A variável `samples` limita **apenas a quantidade de testemunhas exibidas**, não a análise de regiões.

A prova de exatidão exige que o modelo e os intervalos descritos sejam válidos. As saídas são exemplos matemáticos, **não resultados de conexão real**.

## 4. Complexidade e limites

A fragmentação pode crescer de modo combinatório em políticas adversariais. O CLI aceita `--max-fragments` de 100 a 100.000 (padrão 10.000). Ao exceder o limite, **a execução interrompe com status INCONCLUSIVO / exit 3**, nunca apresenta falso PASS. O parser limita arquivo a 1.048.576 bytes, 500 regras, 1.000 assertions e 128 faixas de portas por regra. O motor também aplica limite global de 2.000.000 de operações de subtração por execução de `check`/`diff` para reduzir exaustão de CPU. Mesmo assim, configure timeout externo na CI.

## 5. Heurística FP004 (atenção)

A detecção de serviços administrativos considera somente regras `allow` com **origem exatamente /0** e testa a existência de uma região efetivamente permitida que inclua um dos seguintes IPs públicos de referência: IPv4 `1.1.1.1`, `8.8.8.8`, `9.9.9.9`; IPv6 `2606:4700:4700::1111`, `2001:4860:4860::8888`. As portas administrativas documentadas são 22, 23, 3389, 3306, 5432, 6379 e 9200 (TCP). O alerta fornece um fluxo testemunha no modelo.

A heurística **não detecta todos os possíveis acessos públicos** (por exemplo, origens parcialmente amplas ou IPs públicos distintos das amostras). Tampouco identifica exposição na Internet real, dado que roteamento, NAT, equipamento e ACL upstream não são modelados. Ela reduz ruído; não é um verificador universal de exposição.

## 6. Determinismo, segurança e extensibilidade

Com mesmo arquivo e versão do motor, os resultados de `check`, `diff`, `simulate` e SARIF são determinísticos; nenhuma data volátil é inserida. O CLI adiciona SHA-256 do input ao JSON da análise, garantindo referência ao arquivo analisado, mas **o hash não constitui assinatura**. A impressão SARIF deriva de identificador, regra e evidência; mudanças de evidência geram nova impressão digital.

Extensões futuras recomendadas: proof-carrying policy, normalização de vendor ACL a partir de adaptadores de confiança, combinações de protocolos adicionais e visualização; cada extensão exige novos testes, documentação semântica e revisão de limites.
