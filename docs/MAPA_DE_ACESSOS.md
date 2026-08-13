# Mapa de acessos do SAC 4.0

| Área | Endereço | Público | Gestor |
| --- | --- | --- | --- |
| Site comercial | `https://apps.sactrial.gritnews.com.br/` | Visitantes, leads e clientes em avaliação | Comercial e marketing GRIT |
| Aplicação SAC 4.0 | `https://apps.sactrial.gritnews.com.br/app` | Usuários convidados de empresas com trial ou assinatura | Administrador de cada empresa; módulos definidos pelo contrato |
| Central Gerencial | `https://apps.sactrial.gritnews.com.br/admin` | Somente perfil `SUPERADMIN` | GRIT Soluções e Negócios |
| Aplicação Procirúrgica | `https://apps.sacproh.gritnews.com.br/` | Usuários internos autorizados | Administradores da Procirúrgica |

## Responsabilidades

- O site comercial capta leads, apresenta planos e direciona clientes existentes ao acesso do produto.
- A aplicação autentica cada usuário, aplica o isolamento por empresa e apresenta somente os módulos contratados.
- A Central Gerencial controla empresas, testes, assinaturas, usuários, módulos, engajamento, riscos, alertas e pagamentos.
- O perfil `ADMIN_EMPRESA` administra somente a própria organização dentro da aplicação; ele não acessa a Central Gerencial da GRIT.
- A rota antiga `/sacproh` no domínio do SACTRIAL permanece temporariamente compatível, mas novos links devem usar `/app`.
