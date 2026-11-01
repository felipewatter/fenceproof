# Histórico de mudanças

## [1.0.0] — 2026-11-01

### Implementado
- Motor simbólico exato de intervalos para ACL IPv4/IPv6, TCP/UDP/ICMP.
- Detecção de regras completamente e parcialmente encobertas; default permissivo.
- Identificação conservadora de serviços administrativos alcançáveis a partir de endereços IP públicos amostrados.
- Assertions de política, simulação e diff exato do conjunto de tráfego permitido.
- Relatórios determinísticos (texto, JSON, SARIF 2.1.0) e SHA-256 do arquivo de entrada.
- Tratamento de limites de complexidade com saída INCONCLUSIVA (código 3).
- 43 testes unitários/CLI, exaustivos em espaços pequenos e diferenciais com semente fixa (91% de cobertura local).
- GitHub Actions CI (3 sistemas operacionais × 3 versões de Python); release automatizada **somente após sucesso de CI na main**.
