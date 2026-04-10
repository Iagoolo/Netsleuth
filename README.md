# Netsleuth

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Plataforma-Linux-FCC624?style=flat&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Um analisador forense de tráfego de rede e extrator de arquivos (File Carver) escrito em Go.

O **Netsleuth** foi projetado para capturar tráfego de rede em tempo real, analisar pacotes e extrair evidências (como imagens e páginas HTML) reconstruindo-as diretamente no disco local, utilizando assinaturas digitais (Magic Bytes) para garantir a integridade dos artefatos.

---

## Funcionalidades Atuais

* **Captura de Pacotes em Tempo Real:** Utiliza a biblioteca `gopacket` para ouvir interfaces de rede (ex: Wi-Fi, Ethernet).
* **Filtros BPF (Berkeley Packet Filter):** Permite isolar tráfego específico (ex: `tcp and port 80`).
* **File Carving (Extração HTTP):** Intercepta respostas de servidores e corta pacotes cirurgicamente para separar cabeçalhos de texto dos dados binários.
* **Nomeação Dinâmica:** Previne a sobrescrita de evidências utilizando o IP de origem e o *timestamp* em milissegundos para cada arquivo capturado.
* **Detecção por Magic Bytes:** Identifica o tipo real do arquivo analisando os seus primeiros bytes hexadecimais (DNA do arquivo), em vez de confiar no cabeçalho HTTP.
  * Suporte atual: `.gif`, `.jpg`, `.html`, `.ico`.

---

> ## ⚠️ Aviso Legal (Disclaimer)

Este projeto tem fins **estritamente educacionais e acadêmicos**. Ele foi desenvolvido para o estudo de redes de computadores, arquitetura TCP/IP e análise forense defensiva. O uso desta ferramenta para interceptar tráfego de redes que você não possui autorização explícita para monitorar é estritamente proibido e pode configurar crime.

---

## 🛠️ Requisitos e Instalação

O Netsleuth foi construído em Go e depende da biblioteca C `libpcap` para acessar a placa de rede em modo promíscuo.

### 1. Dependências do Sistema (Linux)

Instale os cabeçalhos de desenvolvimento do pcap:

**Fedora / CentOS / RHEL:**

```bash
sudo dnf install libpcap-devel
```

**Ubuntu / Debian / Kali Linux:**

```bash
sudo apt install libpcap-dev
```

### 2. Baixando e Executando

Clone o repositório e baixe os módulos do Go:

```bash
git clone [https://github.com/Iagoolo/Netsleuth.git](https://github.com/Iagoolo/Netsleuth.git)
cd Netsleuth/netsleuth
go mod tidy
```

Para rodar a ferramenta, você precisa de privilégios de root para abrir a interface de rede:

```bash
sudo go run cmd/netsleuth/main.go
```

> (Nota: O código atual está configurado ('hardcoded') para ouvir a interface wlp1s0. Você pode precisar alterar isso no main.go dependendo do nome da sua placa de rede).

## Arquitetura do Projeto

`cmd/netsleuth/main.go`: O ponto de entrada. Configura as opções de captura e gerencia o laço de escuta.

`internal/capture/`: Módulo responsável por inicializar a placa de rede e aplicar os filtros BPF.

`internal/analyzer/`: O motor de inteligência. Recebe pacotes crus, disseca as camadas (IP/TCP), executa o File Carving e salva as evidências.
