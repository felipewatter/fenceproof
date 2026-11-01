# Matriz de testes

| Critério | Método | Implementação |
| --- | --- | --- |
| Arquivos JSON inválidos, duplicados, grandes ou não canônicos | Testes unitários negativos | `test_parser.py` |
| Limites/portas, famílias e protocolos | Testes unitários | `test_parser.py` |
| Subtração sem sobreposição e cobertura exata | 27 decomposições de espaços discretos pequenos | `test_engine.BoxTests` |
| Guard contra explosão de fragmentos/operações | Testes negativos com 250 cortes e limite de operações | `test_engine.BoxTests` |
| Precedência das regras e shadowing por união | Casos construídos | `test_engine.EngineTests` |
| Comparação IPv4 e IPv6, default allow | Casos construídos | `test_engine.EngineTests` |
| Diferencial simbólico versus oráculo de pacotes | **80 pares de políticas aleatórios reprodutíveis**, com enumeração dos fluxos relevantes | `test_randomized_diff_vs_bruteforce` |
| FP001–FP005 | Casos de política de exemplo | `test_engine.py`, `test_cli_report.py` |
| Saída JSON, texto, SARIF e códigos de saída | Testes CLI | `test_cli_report.py` |
| Portabilidade | GitHub Actions: Ubuntu, Windows, macOS × Python 3.11, 3.12, 3.13 | `.github/workflows/ci.yml` |
| Não emissão de release antes de CI verde | Workflow condicionado a `workflow_run` `success` de `push` na `main` | `.github/workflows/release.yml` |

## Execução local

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m compileall -q src tests
PYTHONPATH=src python -m fenceproof check --policy examples/secure-policy.json --fail-on low
PYTHONPATH=src python -m fenceproof diff --before examples/secure-policy.json --after examples/risky-policy.json --format json
```

O pipeline remoto somente é considerado validado depois que os jobs do GitHub Actions aparecerem como concluídos com sucesso. Não confunda a passagem local com CI remoto.
