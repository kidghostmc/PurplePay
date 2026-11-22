# PurplePay — NexusPag

Painel de cobranças Pix com funções Node.js na Vercel, banco PostgreSQL Neon e confirmação de pagamento validada no servidor.

## Configuração

No projeto Vercel `purplepay`, configure as variáveis de **Production**:

| Variável | Valor |
| --- | --- |
| `APP_ORIGIN` | `https://purplepay-snowy.vercel.app` |
| `DATABASE_URL` | Adicionada ao conectar o banco Neon ao projeto pela Vercel |
| `NEXUS_API_KEY` | Chave da conta recebedora da startup na NexusPag |
| `NEXUS_WEBHOOK_SECRET` | Segredo de assinatura configurado em Integrações / Webhooks na NexusPag |
| `PURPLEPAY_ADMIN_PASSWORD` | Senha exclusiva, com pelo menos 12 caracteres, escolhida pelo administrador |

Mantenha credenciais como variáveis secretas. Não inclua valores no código, em commits, capturas ou mensagens. Alterações nas variáveis exigem uma nova implantação. O usuário de administração é `admin`. O antigo acesso demonstrativo não é aceito. A criação de tabelas é automática na primeira requisição após configurar o banco.

Na NexusPag, habilite a assinatura de webhooks e configure o evento `payment.confirmed` para:

`https://purplepay-snowy.vercel.app/api/nexus/webhook`

Essa mesma URL também é enviada na criação de cada cobrança. O código aceita notificações repetidas sem duplicar a venda. Não habilite credenciais de produção em Preview enquanto `APP_ORIGIN` apontar para o domínio de produção.

## Recebimentos

As cobranças usam exclusivamente a conta dona da chave `NEXUS_API_KEY`. Não são enviados `shop_id`, `split` nem `splits`: os recebimentos ficam na carteira principal, sujeitos às taxas da NexusPag. O projeto não implementa saques nem transferências. Comissões dos atendentes são registros internos calculados sobre o valor bruto; não movimentam dinheiro.

Cada pedido recebe um `external_id` estável. Falhas de rede devem ser repetidas com o mesmo pedido para evitar duplicação. A confirmação exige uma consulta autenticada à NexusPag, verificando identificador, valor e status. Webhooks exigem HMAC-SHA256 sobre o corpo bruto e timestamp recente. Sessões usam cookies HttpOnly/Secure, os atendentes têm senhas derivadas por scrypt, e as rotas validam autorização no servidor.

Os dados demonstrativos que estavam no navegador não são importados para o histórico financeiro real. Atendentes devem ser cadastrados novamente pelo administrador. Desativá-los preserva o histórico.

## Verificação e desenvolvimento

`npm ci`, `npm test`, `npm run build`.

Os testes usam PostgreSQL local em memória (PGlite) e uma NexusPag simulada. Cobrem autenticação, isolamento de atendentes, idempotência, assinatura, divergência de valor e notificações duplicadas. Não geram cobranças reais. `npm run dev` abre a interface em `http://127.0.0.1:4173` para inspeção; sessões de produção exigem HTTPS e a origem canônica configurada.

Antes de operar, o titular deve conferir a conta recebedora e validar o fluxo completo com uma cobrança autorizada de baixo valor, incluindo QR Code, crédito no painel NexusPag e atualização do PurplePay.

## Documentação oficial

- https://nexuspag.com/docs/create-pix
- https://nexuspag.com/docs/get-pix
- https://nexuspag.com/docs/webhook-payment
- https://vercel.com/docs/environment-variables

Somente `public/index.html` é publicado como arquivo estático. Funções, dependências e credenciais ficam fora da pasta pública.
