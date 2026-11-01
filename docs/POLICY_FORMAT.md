# Especificação do formato `policy.json` v1

## Exemplo mínimo

```json
{
  "version": 1,
  "name": "firewall-dmz",
  "default_action": "deny",
  "rules": [
    {
      "id": "permitir-https",
      "action": "allow",
      "src": "any4",
      "dst": "10.0.50.20/32",
      "protocol": "tcp",
      "ports": [443, [8443, 8445]]
    }
  ],
  "assertions": [
    {
      "id": "https-publico",
      "flow": {"src": "1.1.1.1", "dst": "10.0.50.20", "protocol": "tcp", "port": 443},
      "expect": "allow"
    }
  ]
}
```

## Campos

| Campo | Tipo | Observação |
| --- | --- | --- |
| `version` | inteiro | Apenas `1`, não booleano. |
| `name` | identificador ASCII | Começa com letra; letras/números/`_`/`.`/`-`; até 64 caracteres. |
| `default_action` | string | `allow` ou `deny`. Recomenda-se `deny`. |
| `rules` | array | Ordem é relevante; até 500. |
| `rules[].id` | identificador | Único por política; mesma sintaxe de `name`. |
| `rules[].action` | string | `allow` ou `deny`. |
| `rules[].src`, `dst` | CIDR | CIDR canônico (`192.0.2.0/24`, `2001:db8::/32`) ou `any4`/`any6`; mesma família. |
| `rules[].protocol` | string | `tcp`, `udp`, `icmp` ou `any` (apenas estes três). |
| `rules[].ports` | array opcional | Apenas TCP/UDP; número de porta ou `[início,fim]` inclusivo, 1..65535. Omitir significa todas as portas TCP/UDP. |
| `assertions` | array opcional | Até 1.000; cenários para verificação. |
| `assertions[].id` | identificador | Único nas assertions. |
| `assertions[].flow` | objeto | `src` e `dst` como endereços individuais; `protocol` TCP/UDP/ICMP; `port` TCP/UDP 1..65535 ou ICMP 0. |
| `assertions[].expect` | string | `allow` ou `deny`. |

## Sintaxe restrita

- Todas as chaves JSON devem ser únicas; chaves desconhecidas são rejeitadas.
- Endereços IPv4 e IPv6 são avaliados de forma independente, sem tradução entre famílias.
- A máscara CIDR deve estar alinhada com o endereço de rede (ex.: `10.0.0.1/24` é rejeitado; use `10.0.0.0/24`).
- Para `protocol: "any"` ou `"icmp"`, `ports` deve **ser omitido**. `any` inclui TCP, UDP e ICMP, sem portas adicionais.
- Intervalos de portas são unidos e normalizados, garantindo regiões não sobrepostas.
- Limite por arquivo: 1.048.576 bytes. Não existe suporte a imports, includes, placeholders, variáveis ou execução de código.

## Códigos e severidades

| Código | Severidade | Diagnóstico |
| --- | --- | --- |
| `FP001` | Alta | `default_action` é `allow`. |
| `FP002` | Média | Regra inteiramente encoberta por regras anteriores. |
| `FP003` | Baixa | Regra parcialmente encoberta. |
| `FP004` | Alta | Exemplo de acesso permitido a serviço administrativo a partir de IP público amostrado (heurística). |
| `FP005` | Alta | Expectativa de decisão (`assertion`) falhou. |

## Códigos de saída

- `0`: execução concluída, sem achados no limiar configurado (ou `--fail-on none`); em `diff`, diferença permitida sem gate.
- `1`: entrada/parâmetros inválidos, arquivo inacessível ou falha de escrita do relatório.
- `2`: achado no limiar configurado ou `diff --fail-on-change` com alteração.
- `3`: análise **INCONCLUSIVA**, excedeu limite de fragmentos.

Cuidado: `0` **não** implica que o firewall é seguro; somente que os critérios modelados foram atendidos na execução.
