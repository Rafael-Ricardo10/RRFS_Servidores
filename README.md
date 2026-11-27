# 🛡️ RRFS-Servidores

Sistema para **gerenciar servidores Debian ou derivados** (Ubuntu, Mint, Raspberry Pi OS etc.), com **segurança** e **acesso remoto de qualquer lugar do mundo**, sem precisar de IP público nem de domínio.

---

## 🚀 O que o sistema faz

Com ele você configura e gerencia no servidor:

- 🔥 **Firewall**
- 🌐 **Acesso remoto**
- 🦠 **Antivírus**
- 🔐 **DNS seguro**
- 🧱 **AppArmor**

---

## 🌍 Acesso remoto pela rede Tox

O acesso remoto usa o protocolo **[Tox](https://tox.chat/)**, que é descentralizado e criptografado. Com ele você acessa o servidor de **qualquer lugar do mundo, de forma segura**.

O sistema cria um **túnel TCP genérico** pela rede Tox. Por isso ele consegue **liberar portas externas do outro lado** da conexão, e você pode acessar vários serviços do servidor por esse túnel.

### Vantagens

- ✅ **Sem IP público**
- ✅ **Sem domínio**
- ✅ **Sem abrir portas no roteador**
- ✅ Funciona para **servidores domésticos**
- ✅ Acesso de qualquer lugar do mundo
- ✅ Comunicação criptografada

---

## 🔐 Segurança e controle de acesso

### Login no sistema

O login do sistema é feito pelo **usuário root do Debian**.

### Autorização do acesso remoto

Ninguém acessa o servidor sem permissão:

1. O **cliente** precisa ter a **chave** de acesso.
2. No **servidor**, o **administrador precisa aceitar** esse cliente.
3. Sem a aprovação do administrador, o acesso **não é liberado**.

### Firewall automático

O próprio sistema **configura as regras do firewall automaticamente**. As regras necessárias ao funcionamento do sistema são **automáticas**.

O usuário pode **adicionar novas regras** quando quiser.

---

## 📁 Organização do projeto

O projeto é dividido em duas pastas:

| Pasta | Função | Onde usar |
|---|---|---|
| **`cliente`** | Acessa o servidor à distância | No computador que você usa para se conectar ao servidor |
| **`servidor`** | Instala o sistema e gerencia o servidor | No servidor Debian (ou derivado) que será gerenciado |

### Como usar (resumo)

1. Instale a pasta **`servidor`** no servidor que você quer gerenciar.
2. Instale a pasta **`cliente`** no computador de onde você vai acessar.
3. Conecte o cliente ao servidor pela rede Tox.
4. No servidor, o administrador **aceita o cliente**.
5. Gerencie o servidor e use o túnel para acessar os serviços.

---

## 🙏 Agradecimento ao projeto Tox

Um agradecimento especial à comunidade do **projeto Tox**. Por ser **open source**, o protocolo pôde ser adaptado e usado neste projeto para a comunicação segura entre cliente e servidor.

- 🌍 Site oficial: [https://tox.chat](https://tox.chat)
- 💻 Código do protocolo: [github.com/TokTok/c-toxcore](https://github.com/TokTok/c-toxcore)

---

## 🚧 Status do projeto

⚠️ **Em desenvolvimento.** O sistema já está **funcional**, mas ainda recebe melhorias e correções.

Se encontrar algum problema, abra uma **Issue**. Seu feedback ajuda muito!

---

## ❤️ Apoie o projeto

Este é um projeto open source. Doações são muito bem-vindas e me incentivam a continuar desenvolvendo.

| Forma | Chave |
|---|---|
| **PIX** | `0cd822ec-e5a8-48cb-b17f-a9c4233c7b59` |
| **Bitcoin (BTC)** | `bc1qqz3l07skhpvh4k5dzhcgyh342c76f2y4vmka27` |

Obrigado pelo apoio! 🙌

---

## 🤝 Contribuindo

Sugestões, relatos de bugs e contribuições são bem-vindos. Abra uma **Issue** ou envie um **Pull Request**.
