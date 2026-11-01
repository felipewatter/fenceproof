# FenceProof v1.0.0

Primeira versão pública do **FenceProof**, analisador offline de políticas de firewall com auditoria determinística.

## Funcionalidades

- Interpretação de regras de firewall ordenadas (primeira correspondência prevalece).
- IPv4 e IPv6, protocolos TCP/UDP/ICMP, intervalos de portas e política padrão.
- Análise exata de regras completamente ou parcialmente encobertas, inclusive por união de múltiplas regras anteriores.
- Comparação semântica de políticas: tráfego que passou a ser permitido ou negado com fluxo de evidência.
- Verificação de expectativas em cenários (`assertions`) e simulação de pacote.
- Identificação de exposições administrativas com amostras de endereços públicos (FP004, análise heurística).
- Exportação em texto, JSON e SARIF 2.1.0.
- Tratamento explícito de limites computacionais para evitar resultado falso `PASS`.
- Suíte automatizada sem dependências de runtime.

## Instalação e teste

```bash
python -m pip install .
fenceproof check --policy examples/secure-policy.json
python -m unittest discover -s tests -v
```

## Garantias e limites

O resultado é **exato dentro do modelo ACL stateless descrito em `docs/ARCHITECTURE.md`**. Não há integração com firewalls reais, NAT, roteamento, sessão, VPN, identidades ou Camada 7. A detecção de exposição FP004 é heurística e não constitui varredura de rede nem certificação de segurança.

Notas detalhadas, matriz de testes, ameaça e exemplos no README.
