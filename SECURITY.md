# Política de segurança

## Versões suportadas

| Linha | Correções de segurança |
| --- | --- |
| 1.0.x | Suportada |

## Divulgação responsável

Para informar uma vulnerabilidade, prefira **GitHub → Security → Advisories → Report a vulnerability** neste repositório (quando habilitado). Evite abrir issue pública com reproduções exploráveis, segredos ou políticas de rede reais. Inclua versão, comportamento, impacto, reprodução mínima sanitizada e correção sugerida. Não há SLA público comprometido para respostas.

## Modelo de ameaça

Consulte `docs/THREAT_MODEL.md`. O FenceProof analisa arquivos locais e não executa rede, comandos inseridos na política ou código remoto. Os arquivos de política podem revelar endereços e serviços sensíveis — não os publique sem sanitização. O programa não substitui verificação do equipamento real.

## Uso seguro

- Leia políticas de fontes confiáveis ou saneie os dados antes de compartilhá-los.
- Execute o processo sem privilégios administrativos.
- Use `--max-fragments` para limitar análises custosas; o limite padrão é 10.000.
- Mantenha o runner e a distribuição Python atualizados.
- Evite gravar relatórios em diretórios compartilhados, pois os fluxos podem conter topologia da rede.
