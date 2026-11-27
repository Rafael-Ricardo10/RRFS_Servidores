#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         RRFS Servidores - Instalador / Gerenciador          ║
# ║         Execute como root: sudo bash instalar.sh            ║
# ╚══════════════════════════════════════════════════════════════╝

# ── cores ──────────────────────────────────────────────────────
VERDE='\033[0;32m'
AMARELO='\033[1;33m'
VERMELHO='\033[0;31m'
AZUL='\033[0;34m'
CIANO='\033[0;36m'
BRANCO='\033[1;37m'
RESET='\033[0m'

# ── caminhos ───────────────────────────────────────────────────
INSTALL_DIR="/DATA/AppData/RRFS_Servidores"
VENV_DIR="${INSTALL_DIR}/venv"
DADOS_DIR="${INSTALL_DIR}/dados"
SERVICE_NAME="RRFS_Servidores"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
LOG_FILE="${INSTALL_DIR}/dados/logs/erros.log"

# diretório onde o instalador está sendo executado
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── funções de log ─────────────────────────────────────────────
log()    { echo -e "${VERDE}  [✓]${RESET} $1"; }
warn()   { echo -e "${AMARELO}  [!]${RESET} $1"; }
erro()   { echo -e "${VERMELHO}  [✗]${RESET} $1"; }
info()   { echo -e "${AZUL}  [→]${RESET} $1"; }
titulo() { echo -e "\n${CIANO}${BRANCO}$1${RESET}\n"; }

# ── cabeçalho ──────────────────────────────────────────────────
cabecalho() {
    clear
    echo -e "${CIANO}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║           RRFS Servidores - Gerenciador                 ║"
    echo "  ║           Sistema de Segurança de Rede                  ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ── verificar root ─────────────────────────────────────────────
verificar_root() {
    if [ "$(id -u)" -ne 0 ]; then
        erro "Este instalador deve ser executado como root."
        echo -e "  Execute: ${AMARELO}sudo bash instalar.sh${RESET}"
        exit 1
    fi
}

# ── verificar se sistema está instalado ───────────────────────
sistema_instalado() {
    [ -d "${INSTALL_DIR}" ] && \
    [ -f "${INSTALL_DIR}/app.py" ] && \
    [ -d "${VENV_DIR}" ]
}

# ── verificar status do serviço ───────────────────────────────
status_servico() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "ativo"
    elif systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "parado"
    else
        echo "nao_instalado"
    fi
}

# ══════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════

menu_principal() {
    cabecalho

    local status
    status=$(status_servico)
    local instalado
    instalado=$(sistema_instalado && echo "sim" || echo "nao")

    # mostrar status atual
    echo -e "  ${BRANCO}Status do Sistema:${RESET}"

    if [ "${instalado}" = "sim" ]; then
        echo -e "  Instalação: ${VERDE}Encontrada${RESET} → ${INSTALL_DIR}"

        case "${status}" in
            ativo)
                echo -e "  Serviço:    ${VERDE}● Rodando${RESET}"
                ;;
            parado)
                echo -e "  Serviço:    ${AMARELO}● Parado${RESET}"
                ;;
            *)
                echo -e "  Serviço:    ${VERMELHO}● Não registrado${RESET}"
                ;;
        esac

        # versão python do venv
        if [ -f "${VENV_DIR}/bin/python3" ]; then
            local py_ver
            py_ver=$("${VENV_DIR}/bin/python3" --version 2>&1)
            echo -e "  Python:     ${AZUL}${py_ver}${RESET}"
        fi

    else
        echo -e "  Instalação: ${VERMELHO}Não encontrada${RESET}"
        echo -e "  Serviço:    ${VERMELHO}Não instalado${RESET}"
    fi

    echo ""
    echo -e "  ${BRANCO}╔══════════════════════════════╗${RESET}"

    if [ "${instalado}" = "sim" ]; then
        echo -e "  ${BRANCO}║  Opções disponíveis:        ║${RESET}"
        echo -e "  ${BRANCO}╠══════════════════════════════╣${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${VERDE}1${RESET} → Reinstalar / Atualizar  ${BRANCO}║${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${VERMELHO}2${RESET} → Desinstalar             ${BRANCO}║${RESET}"

        if [ "${status}" = "ativo" ]; then
            echo -e "  ${BRANCO}║${RESET}  ${AMARELO}3${RESET} → Parar serviço           ${BRANCO}║${RESET}"
        else
            echo -e "  ${BRANCO}║${RESET}  ${VERDE}3${RESET} → Iniciar serviço         ${BRANCO}║${RESET}"
        fi

        echo -e "  ${BRANCO}║${RESET}  ${AZUL}4${RESET} → Ver status do serviço   ${BRANCO}║${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${AZUL}5${RESET} → Ver logs de erro        ${BRANCO}║${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${BRANCO}0${RESET} → Sair                    ${BRANCO}║${RESET}"
    else
        echo -e "  ${BRANCO}║  Opções disponíveis:        ║${RESET}"
        echo -e "  ${BRANCO}╠══════════════════════════════╣${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${VERDE}1${RESET} → Instalar sistema         ${BRANCO}║${RESET}"
        echo -e "  ${BRANCO}║${RESET}  ${BRANCO}0${RESET} → Sair                    ${BRANCO}║${RESET}"
    fi

    echo -e "  ${BRANCO}╚══════════════════════════════╝${RESET}"
    echo ""
    read -rp "  Digite a opção e pressione Enter: " opcao
    echo ""

    case "${opcao}" in
        1)
            if [ "${instalado}" = "sim" ]; then
                menu_reinstalar
            else
                instalar_sistema
            fi
            ;;
        2)
            if [ "${instalado}" = "sim" ]; then
                desinstalar_sistema
            else
                warn "Sistema não instalado."
            fi
            ;;
        3)
            if [ "${instalado}" = "sim" ]; then
                if [ "${status}" = "ativo" ]; then
                    parar_servico
                else
                    iniciar_servico
                fi
            else
                warn "Sistema não instalado."
            fi
            ;;
        4)
            if [ "${instalado}" = "sim" ]; then
                ver_status
            else
                warn "Sistema não instalado."
            fi
            ;;
        5)
            if [ "${instalado}" = "sim" ]; then
                ver_logs
            else
                warn "Sistema não instalado."
            fi
            ;;
        0)
            echo -e "  ${CIANO}Saindo...${RESET}"
            exit 0
            ;;
        *)
            warn "Opção inválida: ${opcao}"
            sleep 1
            menu_principal
            ;;
    esac
}

# ══════════════════════════════════════════════════════════════
# MENU REINSTALAR
# ══════════════════════════════════════════════════════════════

menu_reinstalar() {
    cabecalho
    echo -e "  ${BRANCO}Reinstalar / Atualizar sistema${RESET}"
    echo ""
    echo -e "  ${AMARELO}O que será feito:${RESET}"
    echo -e "  • Verificar dependências do sistema (apt)"
    echo -e "  • Verificar e atualizar bibliotecas Python (pip)"
    echo -e "  • Parar o serviço"
    echo -e "  • Substituir arquivos do sistema"
    echo -e "  • ${VERDE}Manter pasta 'dados' e ambiente virtual${RESET}"
    echo -e "  • Reiniciar o serviço"
    echo ""
    read -rp "  Confirmar reinstalação? [s/N]: " resp

    if [[ "${resp}" =~ ^[Ss]$ ]]; then
        reinstalar_sistema
    else
        warn "Reinstalação cancelada."
        sleep 1
        menu_principal
    fi
}

# ══════════════════════════════════════════════════════════════
# VERIFICAR DEPENDÊNCIAS DO SISTEMA
# ══════════════════════════════════════════════════════════════

verificar_dep_sistema() {
    titulo "Verificando dependências do sistema..."

    # atualizar lista de pacotes
    info "Atualizando lista de pacotes..."
    apt-get update -qq 2>/dev/null
    log "Lista atualizada."

    # pacotes necessários
    local pacotes=(
        "python3"
        "python3-pip"
        "python3-venv"
        "openssl"
        "ufw"
        "tor"
        "openvpn"
        "easy-rsa"
        "iproute2"
        "curl"
        "net-tools"
        "network-manager"
        "network-manager-openvpn"
        "dnsutils"
        "iptables"
        "procps"
        "iputils-ping"
    )

    local instalar=()

    for pkg in "${pacotes[@]}"; do
        if dpkg -s "${pkg}" &>/dev/null 2>&1; then
            log "Já instalado: ${pkg}"
        else
            warn "Não encontrado: ${pkg}"
            instalar+=("${pkg}")
        fi
    done

    if [ ${#instalar[@]} -gt 0 ]; then
        info "Instalando pacotes faltantes: ${instalar[*]}"
        apt-get install -y -qq "${instalar[@]}" 2>/dev/null
        log "Pacotes instalados: ${instalar[*]}"
    else
        log "Todas as dependências do sistema estão instaladas."
    fi

    # verificar python3-venv especificamente para versão instalada
    local py_ver
    py_ver=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
    local venv_pkg="python${py_ver}-venv"

    if ! dpkg -s "${venv_pkg}" &>/dev/null 2>&1; then
        info "Instalando ${venv_pkg}..."
        apt-get install -y -qq "${venv_pkg}" 2>/dev/null || true
    fi

    # remover restrição EXTERNALLY-MANAGED do Debian
    info "Removendo restrição EXTERNALLY-MANAGED..."
    local ext_managed
    ext_managed=$(find /usr/lib/python3.* \
        -name "EXTERNALLY-MANAGED" 2>/dev/null | head -1)

    if [ -n "${ext_managed}" ]; then
        rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED 2>/dev/null || true
        log "Restrição EXTERNALLY-MANAGED removida."
    else
        log "EXTERNALLY-MANAGED não encontrado (ok)."
    fi
}

# ══════════════════════════════════════════════════════════════
# VERIFICAR / CRIAR AMBIENTE VIRTUAL
# ══════════════════════════════════════════════════════════════

verificar_venv() {
    titulo "Verificando ambiente virtual Python..."

    if [ ! -d "${VENV_DIR}" ]; then
        info "Criando ambiente virtual em ${VENV_DIR}..."
        python3 -m venv "${VENV_DIR}"
        log "Ambiente virtual criado."
    else
        log "Ambiente virtual encontrado: ${VENV_DIR}"
    fi

    # ativar venv
    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"
    log "Ambiente virtual ativado."

    # atualizar pip silenciosamente
    info "Atualizando pip..."
    pip install --upgrade pip -q 2>/dev/null
    log "pip atualizado."
}

# ══════════════════════════════════════════════════════════════
# VERIFICAR / INSTALAR BIBLIOTECAS PIP
# ══════════════════════════════════════════════════════════════

verificar_bibliotecas() {
    titulo "Verificando bibliotecas Python..."

    local req_file="${SOURCE_DIR}/requirements.txt"

    if [ ! -f "${req_file}" ]; then
        erro "requirements.txt não encontrado em ${SOURCE_DIR}"
        exit 1
    fi

    # ativar venv se não estiver ativo
    if [ -z "${VIRTUAL_ENV}" ]; then
        # shellcheck disable=SC1091
        source "${VENV_DIR}/bin/activate"
    fi

    # verificar cada biblioteca
    info "Verificando bibliotecas instaladas..."

    local atualizar=()

    while IFS= read -r linha; do
        # ignorar comentários e linhas vazias
        [[ "${linha}" =~ ^#.*$ ]] && continue
        [[ -z "${linha// }" ]] && continue

        # extrair nome e versão mínima
        local nome versao_min pkg_instalado
        nome=$(echo "${linha}" | grep -oP '^[a-zA-Z0-9_\-]+')
        versao_min=$(echo "${linha}" | grep -oP '>=[\d.]+' | tr -d '>=')

        if [ -z "${nome}" ]; then continue; fi

        # verificar se está instalado
        pkg_instalado=$(pip show "${nome}" 2>/dev/null \
            | grep -i "^Version:" | awk '{print $2}')

        if [ -z "${pkg_instalado}" ]; then
            warn "Não instalado: ${nome}"
            atualizar+=("${nome}")
        else
            # verificar se versão é suficiente
            if [ -n "${versao_min}" ]; then
                local ok
                ok=$(python3 -c "
from packaging.version import Version
try:
    v_inst = Version('${pkg_instalado}')
    v_min  = Version('${versao_min}')
    print('ok' if v_inst >= v_min else 'atualizar')
except:
    print('ok')
" 2>/dev/null || echo "ok")

                if [ "${ok}" = "atualizar" ]; then
                    warn "Desatualizado: ${nome} \
(instalado: ${pkg_instalado}, mínimo: ${versao_min})"
                    atualizar+=("${linha}")
                else
                    log "OK: ${nome} ${pkg_instalado}"
                fi
            else
                log "OK: ${nome} ${pkg_instalado}"
            fi
        fi
    done < "${req_file}"

    # instalar/atualizar apenas o necessário
    if [ ${#atualizar[@]} -gt 0 ]; then
        info "Instalando/atualizando: ${atualizar[*]}"
        pip install -q "${atualizar[@]}"
        log "Bibliotecas atualizadas."
    else
        log "Todas as bibliotecas estão instaladas e atualizadas."
    fi
}

# ══════════════════════════════════════════════════════════════
# CRIAR ESTRUTURA DE DIRETÓRIOS
# ══════════════════════════════════════════════════════════════

criar_diretorios() {
    titulo "Criando estrutura de diretórios..."

    local dirs=(
        "${INSTALL_DIR}"
        "${INSTALL_DIR}/modulos"
        "${INSTALL_DIR}/templates"
        "${DADOS_DIR}"
        "${DADOS_DIR}/ssl"
        "${DADOS_DIR}/logs"
        "${DADOS_DIR}/conexao"
        "${DADOS_DIR}/conexao/vpns"
        "${DADOS_DIR}/conexao/ovpn_acesso"
    )

    for d in "${dirs[@]}"; do
        if [ ! -d "${d}" ]; then
            mkdir -p "${d}"
            log "Criado: ${d}"
        else
            log "Existe: ${d}"
        fi
    done

    # permissões
    chmod 755 "${INSTALL_DIR}"
    chmod 700 "${DADOS_DIR}/ssl"
    chmod 700 "${DADOS_DIR}/conexao/vpns"
    chmod 700 "${DADOS_DIR}/conexao/ovpn_acesso"
    chmod 755 "${DADOS_DIR}/logs"

    log "Permissões aplicadas."
}

# ══════════════════════════════════════════════════════════════
# COPIAR ARQUIVOS DO SISTEMA
# ══════════════════════════════════════════════════════════════

copiar_arquivos() {
    titulo "Copiando arquivos do sistema..."

    # arquivos Python da raiz
    local arquivos_raiz=(
        "app.py"
        "requirements.txt"
    )

    for arq in "${arquivos_raiz[@]}"; do
        if [ -f "${SOURCE_DIR}/${arq}" ]; then
            cp -f "${SOURCE_DIR}/${arq}" "${INSTALL_DIR}/${arq}"
            log "Copiado: ${arq}"
        else
            warn "Não encontrado: ${arq}"
        fi
    done

    # módulos
    if [ -d "${SOURCE_DIR}/modulos" ]; then
        cp -rf "${SOURCE_DIR}/modulos/"* "${INSTALL_DIR}/modulos/"
        log "Módulos copiados."
    else
        warn "Pasta 'modulos' não encontrada em ${SOURCE_DIR}"
    fi

    # templates
    if [ -d "${SOURCE_DIR}/templates" ]; then
        cp -rf "${SOURCE_DIR}/templates/"* "${INSTALL_DIR}/templates/"
        log "Templates copiados."
    else
        warn "Pasta 'templates' não encontrada em ${SOURCE_DIR}"
    fi

    # criar __init__.py nos módulos se não existir
    touch "${INSTALL_DIR}/modulos/__init__.py"

    # permissões dos arquivos
    chmod 750 "${INSTALL_DIR}/app.py"
    chmod 644 "${INSTALL_DIR}/requirements.txt"
    find "${INSTALL_DIR}/modulos" -name "*.py" -exec chmod 644 {} \;
    find "${INSTALL_DIR}/templates" -name "*.html" -exec chmod 644 {} \;

    log "Permissões dos arquivos aplicadas."
}

# ══════════════════════════════════════════════════════════════
# CRIAR SERVIÇO SYSTEMD
# ══════════════════════════════════════════════════════════════

criar_servico() {
    titulo "Criando serviço systemd..."

    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=RRFS Servidores - Sistema de Segurança de Rede
After=network.target ufw.service tor.service
Wants=network.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${VENV_DIR}/bin/python3 ${INSTALL_DIR}/app.py
Restart=on-failure
RestartSec=10
StandardOutput=null
StandardError=append:${LOG_FILE}
SyslogIdentifier=rrfs-servidores
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${INSTALL_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" --quiet 2>/dev/null || true
    log "Serviço ${SERVICE_NAME} criado e habilitado."
}

# ══════════════════════════════════════════════════════════════
# INICIAR SERVIÇO
# ══════════════════════════════════════════════════════════════

iniciar_servico() {
    titulo "Iniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 3

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "Serviço ${SERVICE_NAME} iniciado com sucesso!"
        mostrar_info_acesso
    else
        erro "Falha ao iniciar o serviço!"
        echo ""
        warn "Verificando logs..."
        journalctl -u "${SERVICE_NAME}" --no-pager -n 20 2>/dev/null || true
        if [ -f "${LOG_FILE}" ]; then
            tail -20 "${LOG_FILE}" 2>/dev/null || true
        fi
    fi

    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# PARAR SERVIÇO
# ══════════════════════════════════════════════════════════════

parar_servico() {
    titulo "Parando serviço..."
    systemctl stop "${SERVICE_NAME}"
    sleep 1

    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "Serviço ${SERVICE_NAME} parado."
    else
        warn "Serviço ainda rodando, forçando parada..."
        systemctl kill "${SERVICE_NAME}" 2>/dev/null || true
        sleep 1
        log "Serviço encerrado."
    fi

    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# VER STATUS
# ══════════════════════════════════════════════════════════════

ver_status() {
    titulo "Status do serviço ${SERVICE_NAME}"
    systemctl status "${SERVICE_NAME}" --no-pager 2>/dev/null || true
    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# VER LOGS
# ══════════════════════════════════════════════════════════════

ver_logs() {
    titulo "Logs de erro - últimas 50 linhas"

    if [ -f "${LOG_FILE}" ]; then
        if [ -s "${LOG_FILE}" ]; then
            tail -50 "${LOG_FILE}"
        else
            log "Arquivo de log vazio (sem erros registrados)."
        fi
    else
        warn "Arquivo de log não encontrado: ${LOG_FILE}"
    fi

    echo ""
    echo -e "  ${AZUL}Arquivo:${RESET} ${LOG_FILE}"
    echo -e "  ${AZUL}Dica:${RESET} Para acompanhar em tempo real:"
    echo -e "  ${AMARELO}  tail -f ${LOG_FILE}${RESET}"
    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# MOSTRAR INFO DE ACESSO
# ══════════════════════════════════════════════════════════════

mostrar_info_acesso() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "SEU-IP")

    echo ""
    echo -e "  ${VERDE}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${VERDE}║              Sistema disponível!                        ║${RESET}"
    echo -e "  ${VERDE}╠══════════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ${VERDE}║${RESET}  🌐 Acesso local:  ${CIANO}https://127.0.0.1:2000${RESET}"
    echo -e "  ${VERDE}║${RESET}  🌐 Acesso rede:   ${CIANO}https://${ip}:2000${RESET}"
    echo -e "  ${VERDE}║${RESET}  🔑 Login:         ${AMARELO}senha root do sistema${RESET}"
    echo -e "  ${VERDE}║${RESET}  📋 Logs:          ${AZUL}tail -f ${LOG_FILE}${RESET}"
    echo -e "  ${VERDE}║${RESET}  ⚠️  SSL auto-assinado: aceite o certificado no browser"
    echo -e "  ${VERDE}╚══════════════════════════════════════════════════════════╝${RESET}"
}

# ══════════════════════════════════════════════════════════════
# INSTALAR SISTEMA (nova instalação)
# ══════════════════════════════════════════════════════════════

instalar_sistema() {
    cabecalho
    titulo "Iniciando instalação do RRFS Servidores..."

    # verificar se os arquivos fonte existem
    if [ ! -f "${SOURCE_DIR}/app.py" ]; then
        erro "app.py não encontrado em ${SOURCE_DIR}"
        erro "Execute o instalador a partir da pasta do sistema."
        echo ""
        read -rp "  Pressione Enter para continuar..." _
        menu_principal
        return
    fi

    # executar etapas
    verificar_dep_sistema
    criar_diretorios
    copiar_arquivos
    verificar_venv
    verificar_bibliotecas
    criar_servico

    # iniciar serviço
    titulo "Iniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 4

    echo ""
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "RRFS Servidores instalado e iniciado com sucesso!"
        mostrar_info_acesso
    else
        erro "Serviço não iniciou. Verificando logs..."
        journalctl -u "${SERVICE_NAME}" --no-pager -n 30 2>/dev/null || true
        if [ -f "${LOG_FILE}" ]; then
            echo ""
            warn "Log de erros:"
            tail -20 "${LOG_FILE}" 2>/dev/null || true
        fi
    fi

    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# REINSTALAR / ATUALIZAR SISTEMA
# ══════════════════════════════════════════════════════════════

reinstalar_sistema() {
    cabecalho
    titulo "Reinstalando / Atualizando RRFS Servidores..."

    # verificar arquivos fonte
    if [ ! -f "${SOURCE_DIR}/app.py" ]; then
        erro "app.py não encontrado em ${SOURCE_DIR}"
        erro "Execute o instalador a partir da pasta do sistema."
        echo ""
        read -rp "  Pressione Enter para continuar..." _
        menu_principal
        return
    fi

    # verificar dependências
    verificar_dep_sistema

    # verificar e atualizar bibliotecas pip (venv já existe)
    verificar_venv
    verificar_bibliotecas

    # parar serviço
    titulo "Parando serviço para atualização..."
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        sleep 2
        log "Serviço parado."
    else
        info "Serviço já estava parado."
    fi

    # remover arquivos antigos MANTENDO dados e venv
    titulo "Removendo arquivos antigos do sistema..."

    # listar o que será removido (não dados e não venv)
    local removidos=0
    for item in "${INSTALL_DIR}"/*; do
        local nome_item
        nome_item=$(basename "${item}")

        # preservar pasta dados e venv
        if [ "${nome_item}" = "dados" ] || \
           [ "${nome_item}" = "venv" ]; then
            log "Preservado: ${nome_item}/"
            continue
        fi

        # remover o resto
        rm -rf "${item}"
        info "Removido: ${nome_item}"
        ((removidos++)) || true
    done

    log "Arquivos antigos removidos (${removidos} itens)."

    # recriar estrutura de diretórios (sem apagar dados)
    titulo "Recriando estrutura de diretórios..."
    mkdir -p "${INSTALL_DIR}/modulos"
    mkdir -p "${INSTALL_DIR}/templates"
    mkdir -p "${DADOS_DIR}/ssl"
    mkdir -p "${DADOS_DIR}/logs"
    mkdir -p "${DADOS_DIR}/conexao/vpns"
    mkdir -p "${DADOS_DIR}/conexao/ovpn_acesso"
    log "Estrutura recriada."

    # copiar novos arquivos
    copiar_arquivos

    # recriar serviço (pode ter mudado)
    criar_servico

    # iniciar serviço
    titulo "Reiniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 4

    echo ""
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "RRFS Servidores atualizado e rodando!"

        # mostrar status completo
        titulo "Status do serviço após atualização:"
        systemctl status "${SERVICE_NAME}" \
            --no-pager -l 2>/dev/null | head -20 || true

        mostrar_info_acesso
    else
        erro "Serviço não iniciou após atualização!"
        warn "Verificando logs..."
        journalctl -u "${SERVICE_NAME}" \
            --no-pager -n 30 2>/dev/null || true
        if [ -f "${LOG_FILE}" ]; then
            echo ""
            warn "Erros registrados:"
            tail -20 "${LOG_FILE}" 2>/dev/null || true
        fi
    fi

    echo ""
    read -rp "  Pressione Enter para continuar..." _
    menu_principal
}

# ══════════════════════════════════════════════════════════════
# DESINSTALAR SISTEMA
# ══════════════════════════════════════════════════════════════

desinstalar_sistema() {
    cabecalho
    echo -e "  ${VERMELHO}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "  ${VERMELHO}║           ATENÇÃO - DESINSTALAÇÃO           ║${RESET}"
    echo -e "  ${VERMELHO}╚══════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${AMARELO}Isso irá remover:${RESET}"
    echo -e "  • Todos os arquivos em ${INSTALL_DIR}"
    echo -e "  • Serviço systemd ${SERVICE_NAME}"
    echo -e "  ${VERMELHO}• Incluindo dados, configurações e certificados SSL${RESET}"
    echo ""
    echo -e "  ${BRANCO}Os pacotes do sistema (ufw, tor, openvpn)${RESET}"
    echo -e "  ${BRANCO}NÃO serão removidos.${RESET}"
    echo ""
    read -rp "  Digite 'CONFIRMAR' para desinstalar: " resp

    if [ "${resp}" != "CONFIRMAR" ]; then
        warn "Desinstalação cancelada."
        sleep 1
        menu_principal
        return
    fi

    titulo "Desinstalando RRFS Servidores..."

    # parar e desabilitar serviço
    info "Parando serviço..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    log "Serviço removido."

    # remover diretório completo
    info "Removendo arquivos..."
    if [ -d "${INSTALL_DIR}" ]; then
        rm -rf "${INSTALL_DIR}"
        log "Removido: ${INSTALL_DIR}"
    fi

    # verificar se /DATA ficou vazia
    if [ -d "/DATA/AppData" ]; then
        local count
        count=$(find "/DATA/AppData" -maxdepth 1 \
            -mindepth 1 | wc -l)
        if [ "${count}" -eq 0 ]; then
            rmdir "/DATA/AppData" 2>/dev/null || true
            rmdir "/DATA" 2>/dev/null || true
        fi
    fi

    log "RRFS Servidores desinstalado com sucesso."
    echo ""
    read -rp "  Pressione Enter para sair..." _
    exit 0
}

# ══════════════════════════════════════════════════════════════
# PONTO DE ENTRADA
# ══════════════════════════════════════════════════════════════

verificar_root
menu_principal
