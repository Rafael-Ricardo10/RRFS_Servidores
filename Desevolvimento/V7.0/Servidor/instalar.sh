#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║         RRFS Servidores v2.5 - Instalador / Gerenciador     ║
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

SAIDA_LIBERADA=0

# ── funções de log ─────────────────────────────────────────────
log()    { echo -e "${VERDE}  [✓]${RESET} $1"; }
warn()   { echo -e "${AMARELO}  [!]${RESET} $1"; }
erro()   { echo -e "${VERMELHO}  [✗]${RESET} $1"; }
info()   { echo -e "${AZUL}  [→]${RESET} $1"; }
titulo() { echo -e "\n${CIANO}${BRANCO}$1${RESET}\n"; }
pausar() { echo ""; read -rp "  Pressione Enter para continuar..." _; }

# ── cabeçalho ──────────────────────────────────────────────────
cabecalho() {
    clear
    echo -e "${CIANO}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║           RRFS Servidores v2.5 - Gerenciador            ║"
    echo "  ║           Sistema de Segurança de Rede                  ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

verificar_root() {
    if [ "$(id -u)" -ne 0 ]; then
        erro "Este instalador deve ser executado como root."
        echo -e "  Execute: ${AMARELO}sudo bash instalar.sh${RESET}"
        exit 1
    fi
}

sistema_instalado() {
    [ -d "${INSTALL_DIR}" ] && \
    [ -f "${INSTALL_DIR}/app.py" ] && \
    [ -d "${VENV_DIR}" ]
}

status_servico() {
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "ativo"
    elif systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "parado"
    else
        echo "nao_instalado"
    fi
}

libtox_presente() {
    ldconfig -p 2>/dev/null | grep -q 'libtoxcore\.so'
}

# ══════════════════════════════════════════════════════════════
# VERIFICAÇÕES / UFW
# ══════════════════════════════════════════════════════════════

# Evita apagar os próprios arquivos e confere se o pacote está completo
verificar_origem() {
    if [ "${SOURCE_DIR}" = "${INSTALL_DIR}" ]; then
        erro "O instalador está rodando de dentro de ${INSTALL_DIR}."
        erro "A reinstalação apagaria os próprios arquivos de origem."
        info "Copie a pasta do pacote para outro local (ex.: /root/rrfs) e rode de lá."
        return 1
    fi

    local faltando=0
    for f in app.py requirements.txt modulos/tox_remoto.py \
             modulos/firewall_ufw.py modulos/tor_manager.py \
             templates/dashboard.html templates/tox.html; do
        if [ ! -f "${SOURCE_DIR}/${f}" ]; then
            erro "Arquivo ausente no pacote: ${f}"
            faltando=1
        fi
    done
    [ "${faltando}" -eq 0 ] || return 1

    if [ -f "${SOURCE_DIR}/modulos/conexao.py" ]; then
        warn "modulos/conexao.py (módulo antigo) existe no pacote e será ignorado."
    fi
    return 0
}

# O UFW fica ativo (deny outgoing) mesmo com o RRFS parado. Sem isto,
# apt/git/pip falham silenciosamente durante a reinstalação.
liberar_saida_temporaria() {
    if command -v ufw >/dev/null 2>&1 && \
       ufw status 2>/dev/null | grep -q "Status: active"; then
        info "UFW ativo: liberando tráfego de saída durante a instalação..."
        if ufw default allow outgoing >/dev/null 2>&1; then
            SAIDA_LIBERADA=1
        fi
    fi
}

restaurar_saida() {
    if [ "${SAIDA_LIBERADA}" -eq 1 ]; then
        ufw default deny outgoing >/dev/null 2>&1 || true
        SAIDA_LIBERADA=0
        log "Política de saída do UFW restaurada (deny outgoing)."
    fi
}

perguntar_ssh() {
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        return 0
    fi
    local porta
    porta=$(ss -tlnp 2>/dev/null | awk '/sshd/ {n=split($4,a,":"); print a[n]; exit}')
    porta="${porta:-22}"

    echo ""
    warn "O RRFS ativa o UFW com política 'deny incoming' e 'deny outgoing'."
    warn "Se você administra este servidor por SSH, novas conexões seriam bloqueadas."
    read -rp "  Liberar SSH (${porta}/tcp) no UFW agora? [S/n]: " r
    if [[ ! "${r}" =~ ^[Nn]$ ]]; then
        if ufw allow "${porta}/tcp" >/dev/null 2>&1; then
            log "Regra criada: allow ${porta}/tcp"
        else
            warn "Não foi possível criar a regra (ufw instalado?)."
        fi
    fi
}

# ══════════════════════════════════════════════════════════════
# DEPENDÊNCIAS DO SISTEMA
# ══════════════════════════════════════════════════════════════

verificar_dep_sistema() {
    titulo "Verificando dependências do sistema..."

    info "Atualizando lista de pacotes..."
    if apt-get update -qq >/dev/null 2>&1; then
        log "Lista atualizada."
    else
        warn "apt-get update falhou (sem internet?). Tentando continuar."
    fi

    # VPN/OpenVPN/easy-rsa/NetworkManager removidos (módulo conexao descontinuado)
    local pacotes=(
        "python3"
        "python3-pip"
        "python3-venv"
        "openssl"
        "ufw"
        "tor"
        "iproute2"
        "curl"
        "netcat-openbsd"
        "net-tools"
        "dnsutils"
        "iptables"
        "procps"
        "iputils-ping"
        "logrotate"
        "ca-certificates"
    )

    local instalar=()
    for pkg in "${pacotes[@]}"; do
        if dpkg -s "${pkg}" >/dev/null 2>&1; then
            log "Já instalado: ${pkg}"
        else
            warn "Não encontrado: ${pkg}"
            instalar+=("${pkg}")
        fi
    done

    if [ ${#instalar[@]} -gt 0 ]; then
        info "Instalando pacotes faltantes: ${instalar[*]}"
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y "${instalar[@]}"; then
            erro "Falha ao instalar: ${instalar[*]}"
            return 1
        fi
        log "Pacotes instalados."
    else
        log "Todas as dependências do sistema estão instaladas."
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# LIBTOXCORE (protocolo Tox)
# ══════════════════════════════════════════════════════════════

# Confirma que a biblioteca carrega via ctypes E tem os símbolos usados
testar_libtox() {
    local py="${VENV_DIR}/bin/python3"
    [ -x "${py}" ] || py="python3"
    "${py}" - <<'PYEOF'
import ctypes, ctypes.util, sys
nomes = ["libtoxcore.so", "libtoxcore.so.2", "libtoxcore.so.1", "libtoxcore.so.0"]
p = ctypes.util.find_library("toxcore")
if p:
    nomes.insert(0, p)
for n in nomes:
    try:
        lib = ctypes.CDLL(n)
        for s in ("tox_new", "tox_bootstrap", "tox_add_tcp_relay",
                  "tox_friend_add_norequest", "tox_friend_send_lossless_packet",
                  "tox_self_get_address", "tox_get_savedata"):
            getattr(lib, s)
        print(n)
        sys.exit(0)
    except (OSError, AttributeError):
        continue
sys.exit(1)
PYEOF
}

compilar_libtoxcore() {
    local build log_build rc
    build=$(mktemp -d /tmp/toxcore-build.XXXXXX) || return 1
    log_build="${build}/build.log"

    info "Instalando dependências de compilação..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential cmake pkg-config git libsodium-dev ca-certificates; then
        erro "Falha ao instalar dependências de compilação."
        rm -rf "${build}"
        return 1
    fi

    info "Baixando e compilando c-toxcore (pode levar alguns minutos)..."
    (
        set -e
        cd "${build}"
        git clone --depth 1 --recurse-submodules --shallow-submodules \
            https://github.com/TokTok/c-toxcore.git
        cd c-toxcore
        mkdir _build
        cd _build
        cmake .. -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_TOXAV=OFF -DBOOTSTRAP_DAEMON=OFF \
            -DENABLE_SHARED=ON -DENABLE_STATIC=OFF \
            -DUNITTEST=OFF -DAUTOTEST=OFF
        make -j"$(nproc)"
        make install
    ) > "${log_build}" 2>&1
    rc=$?

    if [ "${rc}" -ne 0 ]; then
        erro "Falha na compilação do c-toxcore. Últimas linhas do log:"
        tail -25 "${log_build}"
        cp -f "${log_build}" /root/toxcore-build.log 2>/dev/null && \
            info "Log completo salvo em /root/toxcore-build.log"
        rm -rf "${build}"
        return 1
    fi

    ldconfig
    rm -rf "${build}"
    return 0
}

instalar_libtoxcore() {
    titulo "Verificando libtoxcore (necessária para o Tox)..."

    if libtox_presente && testar_libtox >/dev/null 2>&1; then
        log "libtoxcore já instalada e compatível."
        return 0
    fi

    info "Tentando instalar via APT (libtoxcore2 / libtoxcore-dev)..."
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        libtoxcore2 libtoxcore-dev >/dev/null 2>&1; then
        ldconfig
        if testar_libtox >/dev/null 2>&1; then
            log "libtoxcore instalada via APT."
            return 0
        fi
        warn "Pacote APT instalado, mas a biblioteca não passou no teste."
    else
        warn "Pacote APT indisponível nesta versão do Debian."
    fi

    warn "Compilando do código-fonte..."
    if ! compilar_libtoxcore; then
        erro "Não foi possível instalar a libtoxcore."
        warn "O RRFS funciona sem ela, mas o módulo Tox ficará indisponível."
        return 1
    fi

    if testar_libtox >/dev/null 2>&1; then
        log "libtoxcore compilada e instalada com sucesso."
        return 0
    fi
    erro "Compilou, mas a biblioteca não carregou via Python."
    return 1
}

# ══════════════════════════════════════════════════════════════
# AMBIENTE VIRTUAL / BIBLIOTECAS PYTHON
# ══════════════════════════════════════════════════════════════

verificar_venv() {
    titulo "Verificando ambiente virtual Python..."

    if [ ! -x "${VENV_DIR}/bin/python3" ]; then
        info "Criando ambiente virtual em ${VENV_DIR}..."
        rm -rf "${VENV_DIR}"
        if ! python3 -m venv "${VENV_DIR}"; then
            erro "Falha ao criar o ambiente virtual (python3-venv instalado?)."
            return 1
        fi
        log "Ambiente virtual criado."
    else
        log "Ambiente virtual encontrado: ${VENV_DIR}"
    fi

    # shellcheck disable=SC1091
    source "${VENV_DIR}/bin/activate"

    info "Atualizando pip..."
    pip install --upgrade pip -q >/dev/null 2>&1 || warn "Não foi possível atualizar o pip."
    log "Ambiente virtual ativo."
    return 0
}

verificar_bibliotecas() {
    titulo "Instalando/verificando bibliotecas Python..."

    local req_file="${SOURCE_DIR}/requirements.txt"
    if [ ! -f "${req_file}" ]; then
        erro "requirements.txt não encontrado em ${SOURCE_DIR}"
        return 1
    fi

    if [ -z "${VIRTUAL_ENV}" ]; then
        # shellcheck disable=SC1091
        source "${VENV_DIR}/bin/activate"
    fi

    # pip é idempotente: só baixa o que falta ou está abaixo do mínimo
    if ! pip install -q -r "${req_file}"; then
        erro "Falha ao instalar as bibliotecas de requirements.txt"
        return 1
    fi
    log "Bibliotecas instaladas/atualizadas."

    if ! python3 -c "import flask, paramiko" 2>/dev/null; then
        erro "Import de flask/paramiko falhou no ambiente virtual."
        return 1
    fi
    log "flask e paramiko OK."

    if python3 -c "import pam" 2>/dev/null; then
        log "python-pam OK (login via PAM)."
    else
        warn "python-pam não importou; o login usará /etc/shadow (só funciona no Python < 3.13)."
    fi
    return 0
}

# ══════════════════════════════════════════════════════════════
# DIRETÓRIOS / ARQUIVOS
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
        "${DADOS_DIR}/tox"
    )

    for d in "${dirs[@]}"; do
        if [ ! -d "${d}" ]; then
            mkdir -p "${d}"
            log "Criado: ${d}"
        else
            log "Existe: ${d}"
        fi
    done

    chmod 755 "${INSTALL_DIR}"
    chmod 700 "${DADOS_DIR}"
    chmod 700 "${DADOS_DIR}/ssl"
    chmod 700 "${DADOS_DIR}/tox"
    chmod 755 "${DADOS_DIR}/logs"
    log "Permissões aplicadas."
}

copiar_arquivos() {
    titulo "Copiando arquivos do sistema..."

    for arq in app.py requirements.txt; do
        if [ -f "${SOURCE_DIR}/${arq}" ]; then
            cp -f "${SOURCE_DIR}/${arq}" "${INSTALL_DIR}/${arq}"
            log "Copiado: ${arq}"
        else
            warn "Não encontrado: ${arq}"
        fi
    done

    if [ -d "${SOURCE_DIR}/modulos" ]; then
        cp -rf "${SOURCE_DIR}/modulos/"* "${INSTALL_DIR}/modulos/"
        log "Módulos copiados."
    else
        warn "Pasta 'modulos' não encontrada em ${SOURCE_DIR}"
    fi

    if [ -d "${SOURCE_DIR}/templates" ]; then
        cp -rf "${SOURCE_DIR}/templates/"* "${INSTALL_DIR}/templates/"
        log "Templates copiados."
    else
        warn "Pasta 'templates' não encontrada em ${SOURCE_DIR}"
    fi

    touch "${INSTALL_DIR}/modulos/__init__.py"
    # módulo descontinuado nunca deve ir para a instalação
    rm -f "${INSTALL_DIR}/modulos/conexao.py" "${INSTALL_DIR}/templates/conexao.html"

    chmod 750 "${INSTALL_DIR}/app.py"
    chmod 644 "${INSTALL_DIR}/requirements.txt"
    find "${INSTALL_DIR}/modulos" -name "*.py" -exec chmod 644 {} \;
    find "${INSTALL_DIR}/templates" -name "*.html" -exec chmod 644 {} \;
    log "Permissões dos arquivos aplicadas."
}

# Restos do antigo módulo conexao (VPNs, com usuário/senha)
limpar_legado_conexao() {
    pkill -f 'openvpn-rrfs' 2>/dev/null || true

    if [ -d "${DADOS_DIR}/conexao" ]; then
        titulo "Dados do módulo de conexão antigo"
        warn "Encontrado ${DADOS_DIR}/conexao (VPNs importadas; podem conter usuário/senha)."
        warn "O módulo foi removido, então esses dados não são mais usados."
        read -rp "  Apagar com segurança (shred)? [s/N]: " r
        if [[ "${r}" =~ ^[Ss]$ ]]; then
            find "${DADOS_DIR}/conexao" -type f -exec shred -u {} \; 2>/dev/null || true
            rm -rf "${DADOS_DIR}/conexao"
            log "dados/conexao removido."
        else
            info "Mantido. Você pode apagar depois: rm -rf ${DADOS_DIR}/conexao"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════
# SERVIÇO SYSTEMD
# ══════════════════════════════════════════════════════════════

criar_servico() {
    titulo "Criando serviço systemd..."

    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=RRFS Servidores - Sistema de Segurança de Rede
After=network-online.target ufw.service
Wants=network-online.target
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

    cat > /etc/logrotate.d/rrfs-servidores << EOF
${DADOS_DIR}/logs/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    copytruncate
}
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" --quiet 2>/dev/null || true
    log "Serviço ${SERVICE_NAME} criado e habilitado."
}

iniciar_servico() {
    titulo "Iniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 3

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "Serviço ${SERVICE_NAME} iniciado com sucesso!"
        mostrar_info_acesso
    else
        erro "Falha ao iniciar o serviço!"
        mostrar_erros
    fi
    pausar
    menu_principal
}

mostrar_erros() {
    warn "Verificando logs..."
    journalctl -u "${SERVICE_NAME}" --no-pager -n 20 2>/dev/null || true
    if [ -f "${LOG_FILE}" ]; then
        echo ""
        warn "Log de erros:"
        tail -20 "${LOG_FILE}" 2>/dev/null || true
    fi
}

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
    warn "O UFW continua ativo com as regras do RRFS."
    pausar
    menu_principal
}

ver_status() {
    titulo "Status do serviço ${SERVICE_NAME}"
    systemctl status "${SERVICE_NAME}" --no-pager 2>/dev/null || true
    pausar
    menu_principal
}

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
    echo -e "  ${AZUL}Tempo real:${RESET} ${AMARELO}tail -f ${LOG_FILE}${RESET}"
    pausar
    menu_principal
}

mostrar_info_acesso() {
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    ip="${ip:-SEU-IP}"

    echo ""
    echo -e "  ${VERDE}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "  ${VERDE}║              Sistema disponível!                        ║${RESET}"
    echo -e "  ${VERDE}╠══════════════════════════════════════════════════════════╣${RESET}"
    echo -e "  ${VERDE}║${RESET}  🌐 Acesso local:  ${CIANO}https://127.0.0.1:2000${RESET}"
    echo -e "  ${VERDE}║${RESET}  🌐 Acesso rede:   ${CIANO}https://${ip}:2000${RESET}"
    echo -e "  ${VERDE}║${RESET}  🔑 Login:         ${AMARELO}senha root do sistema${RESET}"
    echo -e "  ${VERDE}║${RESET}  📋 Logs:          ${AZUL}tail -f ${LOG_FILE}${RESET}"
    echo -e "  ${VERDE}║${RESET}  ⚠️  SSL auto-assinado: aceite o certificado no browser"
    echo -e "  ${VERDE}║${RESET}  🔥 UFW agora bloqueia entrada E saída: libere o que precisar"
    echo -e "  ${VERDE}╚══════════════════════════════════════════════════════════╝${RESET}"
}

# ══════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════

menu_principal() {
    cabecalho

    local status instalado
    status=$(status_servico)
    instalado=$(sistema_instalado && echo "sim" || echo "nao")

    echo -e "  ${BRANCO}Status do Sistema:${RESET}"

    if [ "${instalado}" = "sim" ]; then
        echo -e "  Instalação: ${VERDE}Encontrada${RESET} → ${INSTALL_DIR}"
        case "${status}" in
            ativo)  echo -e "  Serviço:    ${VERDE}● Rodando${RESET}" ;;
            parado) echo -e "  Serviço:    ${AMARELO}● Parado${RESET}" ;;
            *)      echo -e "  Serviço:    ${VERMELHO}● Não registrado${RESET}" ;;
        esac
        if [ -x "${VENV_DIR}/bin/python3" ]; then
            echo -e "  Python:     ${AZUL}$("${VENV_DIR}/bin/python3" --version 2>&1)${RESET}"
        fi
    else
        echo -e "  Instalação: ${VERMELHO}Não encontrada${RESET}"
        echo -e "  Serviço:    ${VERMELHO}Não instalado${RESET}"
    fi

    if libtox_presente; then
        echo -e "  libtoxcore: ${VERDE}● Instalada${RESET}"
    else
        echo -e "  libtoxcore: ${AMARELO}● Não instalada${RESET}"
    fi

    echo ""
    echo -e "  ${BRANCO}Opções disponíveis:${RESET}"
    echo -e "  ${BRANCO}──────────────────────────────${RESET}"

    if [ "${instalado}" = "sim" ]; then
        echo -e "  ${VERDE}1${RESET} → Reinstalar / Atualizar"
        echo -e "  ${VERMELHO}2${RESET} → Desinstalar"
        if [ "${status}" = "ativo" ]; then
            echo -e "  ${AMARELO}3${RESET} → Parar serviço"
        else
            echo -e "  ${VERDE}3${RESET} → Iniciar serviço"
        fi
        echo -e "  ${AZUL}4${RESET} → Ver status do serviço"
        echo -e "  ${AZUL}5${RESET} → Ver logs de erro"
        echo -e "  ${AZUL}6${RESET} → Instalar / reparar libtoxcore (Tox)"
    else
        echo -e "  ${VERDE}1${RESET} → Instalar sistema"
        echo -e "  ${AZUL}6${RESET} → Instalar / reparar libtoxcore (Tox)"
    fi
    echo -e "  ${BRANCO}0${RESET} → Sair"
    echo ""
    read -rp "  Digite a opção e pressione Enter: " opcao
    echo ""

    case "${opcao}" in
        1)
            if [ "${instalado}" = "sim" ]; then menu_reinstalar; else instalar_sistema; fi
            ;;
        2)
            if [ "${instalado}" = "sim" ]; then desinstalar_sistema
            else warn "Sistema não instalado."; sleep 1; menu_principal; fi
            ;;
        3)
            if [ "${instalado}" = "sim" ]; then
                if [ "${status}" = "ativo" ]; then parar_servico; else iniciar_servico; fi
            else warn "Sistema não instalado."; sleep 1; menu_principal; fi
            ;;
        4)
            if [ "${instalado}" = "sim" ]; then ver_status
            else warn "Sistema não instalado."; sleep 1; menu_principal; fi
            ;;
        5)
            if [ "${instalado}" = "sim" ]; then ver_logs
            else warn "Sistema não instalado."; sleep 1; menu_principal; fi
            ;;
        6)
            liberar_saida_temporaria
            instalar_libtoxcore
            restaurar_saida
            pausar
            menu_principal
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

menu_reinstalar() {
    cabecalho
    echo -e "  ${BRANCO}Reinstalar / Atualizar sistema${RESET}"
    echo ""
    echo -e "  ${AMARELO}O que será feito:${RESET}"
    echo -e "  • Verificar dependências do sistema (apt) e a libtoxcore"
    echo -e "  • Atualizar bibliotecas Python (pip)"
    echo -e "  • Parar o serviço e substituir os arquivos do sistema"
    echo -e "  • ${VERDE}Manter a pasta 'dados' (inclui a identidade Tox) e o venv${RESET}"
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
# INSTALAR / REINSTALAR / DESINSTALAR
# ══════════════════════════════════════════════════════════════

falha_etapa() {
    erro "$1"
    restaurar_saida
    pausar
    menu_principal
}

instalar_sistema() {
    cabecalho
    titulo "Iniciando instalação do RRFS Servidores..."

    verificar_origem || { pausar; menu_principal; return; }

    liberar_saida_temporaria
    verificar_dep_sistema   || { falha_etapa "Instalação interrompida (dependências)."; return; }
    criar_diretorios
    copiar_arquivos
    verificar_venv          || { falha_etapa "Instalação interrompida (venv)."; return; }
    verificar_bibliotecas   || { falha_etapa "Instalação interrompida (bibliotecas)."; return; }
    instalar_libtoxcore     || warn "Continuando sem libtoxcore (instale depois pela opção 6)."
    criar_servico
    perguntar_ssh

    titulo "Iniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 4
    restaurar_saida

    echo ""
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "RRFS Servidores instalado e iniciado com sucesso!"
        mostrar_info_acesso
    else
        erro "Serviço não iniciou."
        mostrar_erros
    fi
    pausar
    menu_principal
}

reinstalar_sistema() {
    cabecalho
    titulo "Reinstalando / Atualizando RRFS Servidores..."

    verificar_origem || { pausar; menu_principal; return; }

    liberar_saida_temporaria
    verificar_dep_sistema   || { falha_etapa "Atualização interrompida (dependências)."; return; }
    verificar_venv          || { falha_etapa "Atualização interrompida (venv)."; return; }
    verificar_bibliotecas   || { falha_etapa "Atualização interrompida (bibliotecas)."; return; }
    instalar_libtoxcore     || warn "Continuando sem libtoxcore (instale depois pela opção 6)."

    titulo "Parando serviço para atualização..."
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl stop "${SERVICE_NAME}"
        sleep 2
        log "Serviço parado."
    else
        info "Serviço já estava parado."
    fi

    titulo "Removendo arquivos antigos do sistema..."
    local removidos=0 item nome_item
    for item in "${INSTALL_DIR}"/*; do
        nome_item=$(basename "${item}")
        if [ "${nome_item}" = "dados" ] || [ "${nome_item}" = "venv" ]; then
            log "Preservado: ${nome_item}/"
            continue
        fi
        rm -rf "${item}"
        info "Removido: ${nome_item}"
        ((removidos++)) || true
    done
    log "Arquivos antigos removidos (${removidos} itens)."

    criar_diretorios
    copiar_arquivos
    limpar_legado_conexao
    criar_servico
    perguntar_ssh

    titulo "Reiniciando serviço..."
    systemctl start "${SERVICE_NAME}"
    sleep 4
    restaurar_saida

    echo ""
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "RRFS Servidores atualizado e rodando!"
        systemctl status "${SERVICE_NAME}" --no-pager -l 2>/dev/null | head -20 || true
        mostrar_info_acesso
    else
        erro "Serviço não iniciou após atualização!"
        mostrar_erros
    fi
    pausar
    menu_principal
}

desinstalar_sistema() {
    cabecalho
    echo -e "  ${VERMELHO}╔══════════════════════════════════════════════╗${RESET}"
    echo -e "  ${VERMELHO}║           ATENÇÃO - DESINSTALAÇÃO           ║${RESET}"
    echo -e "  ${VERMELHO}╚══════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "  ${AMARELO}Isso irá remover:${RESET}"
    echo -e "  • Todos os arquivos em ${INSTALL_DIR}"
    echo -e "  • Serviço systemd ${SERVICE_NAME}, cron e logrotate do RRFS"
    echo -e "  ${VERMELHO}• Dados, configurações, certificados SSL e a IDENTIDADE TOX"
    echo -e "    (a chave privada do Tox não pode ser recuperada)${RESET}"
    echo ""
    echo -e "  ${BRANCO}Pacotes do sistema (ufw, tor, libtoxcore) NÃO serão removidos.${RESET}"
    echo -e "  ${BRANCO}As regras do UFW criadas pelo RRFS permanecem.${RESET}"
    echo ""
    read -rp "  Digite 'CONFIRMAR' para desinstalar: " resp

    if [ "${resp}" != "CONFIRMAR" ]; then
        warn "Desinstalação cancelada."
        sleep 1
        menu_principal
        return
    fi

    titulo "Desinstalando RRFS Servidores..."

    info "Parando serviço..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}" /etc/logrotate.d/rrfs-servidores
    systemctl disable rrfs-dns-boot.service 2>/dev/null || true
    rm -f /etc/systemd/system/rrfs-dns-boot.service /usr/local/bin/rrfs-dns-boot.sh
    rm -f /etc/cron.d/rrfs-updates /etc/cron.d/rrfs-clamav
    systemctl daemon-reload
    log "Serviço e agendamentos removidos."

    info "Removendo arquivos..."
    if [ -d "${INSTALL_DIR}" ]; then
        rm -rf "${INSTALL_DIR}"
        log "Removido: ${INSTALL_DIR}"
    fi

    if [ -d "/DATA/AppData" ]; then
        local count
        count=$(find "/DATA/AppData" -maxdepth 1 -mindepth 1 | wc -l)
        if [ "${count}" -eq 0 ]; then
            rmdir "/DATA/AppData" 2>/dev/null || true
            rmdir "/DATA" 2>/dev/null || true
        fi
    fi

    if command -v ufw >/dev/null 2>&1 && \
       ufw status verbose 2>/dev/null | grep -qi "deny (outgoing)"; then
        echo ""
        warn "O UFW ainda bloqueia todo tráfego de SAÍDA (o servidor ficará sem internet)."
        read -rp "  Permitir saída novamente (ufw default allow outgoing)? [S/n]: " r
        if [[ ! "${r}" =~ ^[Nn]$ ]]; then
            ufw default allow outgoing >/dev/null 2>&1 && log "Saída liberada."
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
