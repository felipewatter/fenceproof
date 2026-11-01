# Contribuindo com o FenceProof

1. Abra uma issue descrevendo o caso de uso com topologia e endereços fictícios.
2. Crie uma branch específica, com alterações pequenas e revisão de segurança.
3. Acrescente teste que falha antes da correção e passa depois.
4. Execute `make check` (ou comandos equivalentes no Windows).
5. Documente qualquer alteração na semântica do modelo ACL, nos resultados SARIF e no limite de complexidade.
6. Envie um pull request sem segredos, logs internos ou dados de redes reais.

Não introduza chamadas de rede, subprocessos, carregamento de plugins dinâmicos ou parser YAML sem uma avaliação explícita no modelo de ameaças. A licença do projeto é MIT.
