# Modelo de ameaças — STRIDE adaptado

## Ativos

1. Integridade das decisões produzidas pelo analisador.
2. Confidencialidade dos arquivos de política e da topologia.
3. Integridade dos relatórios e rastreabilidade à entrada.
4. Disponibilidade do processo de CI executando políticas potencialmente complexas.

## Confiança e atores

- **Confiável:** binário/código-fonte auditado, runtime Python, máquina de execução e repositório autenticado.
- **Não confiável:** conteúdos do arquivo JSON e parâmetros fornecidos ao CLI.
- **Fora do perímetro:** equipamento de firewall, rede real, credenciais do fornecedor e mudanças remotas de configuração.

| Categoria | Ameaça | Mitigação / risco residual |
| --- | --- | --- |
| Spoofing | Política falsificada como aprovada | SHA-256 documenta bytes, mas não atesta autenticidade: provenance da fonte é responsabilidade externa. |
| Tampering | Entrada JSON ambígua ou regras fora do escopo | Campos desconhecidos, chaves duplicadas, CIDRs não canônicos, portas inválidas e versão inesperada são rejeitados. |
| Repudiation | Contestação da política analisada | Saída determinística com digest SHA-256 e hashes próprios do diff. Não oferece prova criptográfica de autoria. |
| Information Disclosure | Vazamento de topologia em logs ou SARIF | Execução offline; revisão do relatório antes do upload; não coletar dados de produção em exemplos ou issues. |
| Denial of Service | Explosão de estados por combinações de regras | Limites de bytes, número de regras/faixas, fragmentos e operações; status inconclusivo; timeout externo recomendado. |
| Elevation of Privilege | Política injeta comandos ou códigos | Apenas JSON nativo, sem `eval`, execução de shell, plugins, downloads ou interpretação de objetos Python. |

## Propriedades verificadas

- O motor de simulação respeita estritamente primeira correspondência.
- O `diff` compara conjuntos efetivos de tráfego permitido, não apenas diferenças textuais.
- O shadowing pode resultar da **união de regras anteriores**.
- Em cenários com limites esgotados, o sistema não afirma conclusão.
- Nenhuma requisição de rede é necessária no runtime.

## Não garantias

O FenceProof não realiza análise de dispositivos reais, ataques, reconhecimento de serviços, descoberta de ativos, varredura de portas, verificação de segurança universal, priorização de CVEs ou certificação de conformidade. Ele também não modela regras por interface/zone, estado de sessão, pacotes fragmentados, NAT, DNS, rotas, MTU, aplicação, identidade e protocolos não listados.

## Riscos residuais

- Bug no algoritmo simbólico pode provocar conclusão incorreta; testes exaustivos em espaços pequenos e diferencial são controles, não prova universal do programa.
- Dados sensíveis podem ser inseridos pelo operador e exportados no SARIF.
- Políticas com `default_action=allow` geram amplas regiões simbólicas e podem aumentar custo computacional.
- A heurística de porta administrativa não abrange todos os IPs públicos nem portas customizadas.
