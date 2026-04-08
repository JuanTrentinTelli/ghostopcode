# Security Policy

## Uso Autorizado

GhostOpcode é uma ferramenta de reconhecimento ofensivo
desenvolvida exclusivamente para uso em ambientes autorizados.

**O uso deste software implica a aceitação integral das seguintes condições:**

- Você possui autorização explícita e por escrito do proprietário
  do sistema alvo antes de qualquer execução
- Você é o único responsável pelo uso que fizer desta ferramenta
- Os autores não se responsabilizam por uso indevido, ilegal
  ou não autorizado sob nenhuma circunstância
- O uso não autorizado pode constituir crime nos termos da
  Lei Geral de Proteção de Dados (LGPD), Lei de Crimes
  Informáticos (Lei 12.737/2012) e legislações equivalentes
  em outras jurisdições

---

## Versões Suportadas

| Versão | Suportada          |
|--------|--------------------|
| 1.9.x  | ✅ atual           |
| 1.8.x  | ✅ correções críticas |
| < 1.8  | ❌ sem suporte     |

---

## Reportando Vulnerabilidades no GhostOpcode

Se você encontrou uma vulnerabilidade de segurança no próprio
código do GhostOpcode (não em alvos externos), siga o processo
de disclosure responsável:

### O que reportar
- Vulnerabilidades que permitam execução de código arbitrário
- Falhas que exponham dados sensíveis do operador
- Bypass de controles de segurança do framework
- Dependências com CVEs críticos

### Como reportar
1. **Não abra uma Issue pública** com detalhes da vulnerabilidade
2. Abra uma Issue com título `[SECURITY] descrição genérica`
   ou entre em contato diretamente com o mantenedor
3. Inclua: descrição, passos para reproduzir, impacto estimado,
   versão afetada

### O que esperar
- Confirmação de recebimento em até 72 horas
- Avaliação e classificação de severidade
- Patch na próxima release se confirmada
- Crédito no changelog se desejado

---

## Boas Práticas de Uso

```bash
# Sempre confirme autorização antes de qualquer módulo ativo
# O GhostOpcode exige CONFIRM explícito para módulos invasivos:
# nuclei, port scan vuln, packet sniffer

# Armazene outputs com controle de acesso
chmod 700 output/

# Não commite arquivos de output com dados de alvos reais
echo "output/" >> .gitignore
```

---

## Contato

Mantenedor: **GhostOpcode Project**  
Repositório: `git@github.com:JuanTrentinTelli/ghostopcode.git`

---

*Este projeto segue os princípios de Ethical Hacking e
Responsible Disclosure. Use com responsabilidade.*
