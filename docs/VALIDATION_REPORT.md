# Evidência de validação — FenceProof v1.0.0

**Data:** 2026-11-01  
**Ambiente executado:** Python 3.13.5 (Linux), instalação local sem acesso a equipamentos de rede.

## Execuções realizadas

| Verificação | Resultado | Detalhes |
| --- | --- | --- |
| Testes automatizados | **PASS** | 43 testes; `python -m unittest discover -s tests -v`. |
| Cobertura de instruções e ramos | **91% total** | `coverage run --branch --source=fenceproof -m unittest discover -s tests` seguido de `coverage report -m`. |
| Oráculo diferencial de diff | **PASS** | 80 pares de políticas geradas com semente fixa confrontadas contra avaliação direta de pacotes em domínio finito. |
| Oráculo diferencial de shadowing | **PASS** | 80 políticas aleatórias confrontadas contra avaliação direta de precedência. |
| Álgebra de intervalos | **PASS** | 27 casos de decomposição de caixas em espaço pequeno, verificando não sobreposição e cobertura exata. |
| Sintaxe Python | **PASS** | `python -m compileall -q src tests`. |
| CLI de política segura | **PASS** | Exit 0, quatro assertions satisfeitas, sem achados no conjunto de verificações modeladas. |
| CLI de política insegura | **PASS** | Exit 2, achados FP002/FP004/FP005 conforme caso de teste. |
| Diff entre políticas | **PASS** | Detectada nova permissão de origem pública ao destino de teste (SSH, porta TCP 22). |
| Serialização SARIF 2.1.0 | **PASS estrutural** | JSON parseável, versão 2.1.0, resultados e descritores testados; não houve upload ao GitHub Code Scanning. |
| YAML workflows | **PASS sintático** | Arquivos lidos por parser YAML; gatilhos `push`, `pull_request`, `workflow_dispatch`, `workflow_run`. |
| Imports de runtime | **PASS da verificação estática** | Nenhum import de `requests`, `socket`, `subprocess`, `http`, `urllib` ou `pickle` no pacote. Isso não é prova formal de ausência de rede. |
| Construção wheel | **PASS** | `pip wheel . --no-build-isolation --no-deps`, pacote `fenceproof-1.0.0-py3-none-any.whl`. |
| Instalação wheel | **PASS** | Instalação em venv; comandos `fenceproof check` e `fenceproof simulate` executados após instalação. |

## Não executado — limites da evidência

1. **GitHub Actions em Ubuntu/Windows/macOS e Python 3.11/3.12/3.13:** os nove jobs foram configurados, mas ainda não executados no GitHub. Não afirmar status verde remoto antes de verificar a aba Actions.
2. **Publicação de `v1.0.0`:** o workflow condicionado à CI está preparado; a publicação real depende da criação do repositório e do primeiro `push` para a branch `main`.
3. **Validação de aderência a equipamentos físicos:** fora do escopo deliberadamente, já que a ferramenta analisa um modelo próprio stateless.
4. **Compatibilidade integral do SARIF com Code Scanning:** o arquivo segue a estrutura SARIF 2.1.0 e testes de campos, mas não houve teste de importação na interface do GitHub.

## Reproduzir

```bash
python -m pip install .
python -m unittest discover -s tests -v
python -m compileall -q src tests
fenceproof check --policy examples/secure-policy.json --fail-on low
fenceproof check --policy examples/risky-policy.json
fenceproof diff --before examples/secure-policy.json --after examples/risky-policy.json --fail-on-change
```

O segundo comando `check` e o `diff --fail-on-change` **devem** terminar com código `2` nos exemplos fornecidos; isso indica detecção intencional, não defeito.
