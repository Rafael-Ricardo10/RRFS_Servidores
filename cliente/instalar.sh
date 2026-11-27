#!/usr/bin/env bash
# =====================================================================
#  RRFS Servidores - Instalador do Cliente Tox (versão DISTROBOX)
#  Host: Debian 13 (ou derivado) limpo + KDE Plasma
#
#  Ideia: o sistema do usuário fica LIMPO. Todo o cliente (Python,
#  libtoxcore, bibliotecas) roda dentro de um container Debian
#  (distrobox) como usuário comum, sem root no sistema.
#
#  Uso:
#     ./instalar.sh                          instala / atualiza
#     ./instalar.sh --desinstalar            remove o app (mantém dados Tox)
#     ./instalar.sh --desinstalar --tudo     remove também os dados Tox
#     ./instalar.sh --desinstalar --container   remove também o container
#
#  Rode como USUÁRIO COMUM. A senha de ROOT só é pedida (via "su") se o
#  distrobox/podman ainda não estiverem instalados no sistema.
# =====================================================================
set -u

NOME_APP="RRFS Servidores"
ID_APP="rrfs-servidor"
PORTA=2100

CONTAINER="debian"                       # nome do container distrobox
IMAGEM="docker.io/library/debian:13"     # imagem usada se for preciso criar

ORIGEM="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$HOME/.local/share/RRFS-Servidor"
VENV_DIR="$APP_DIR/env"
STATIC_DIR="$APP_DIR/static"
APPS_DIR="$HOME/.local/share/applications"
ICONS_DIR="$HOME/.local/share/icons/hicolor"
AUTOSTART_DIR="$HOME/.config/autostart"
DESKTOP_USER="$APPS_DIR/$ID_APP.desktop"
DESKTOP_AUTOSTART="$AUTOSTART_DIR/$ID_APP.desktop"
LAUNCHER="$APP_DIR/executar.sh"
CONF_CONTAINER="$APP_DIR/container.conf"

if [ -t 1 ]; then V=$'\e[32m'; A=$'\e[33m'; R=$'\e[31m'; C=$'\e[36m'; N=$'\e[0m'; else V=""; A=""; R=""; C=""; N=""; fi
info() { echo "${C}[*]${N} $*"; }
ok()   { echo "${V}[OK]${N} $*"; }
warn() { echo "${A}[AVISO]${N} $*"; }
erro() { echo "${R}[ERRO]${N} $*" >&2; }

if [ "$(id -u)" -eq 0 ]; then
    erro "Não execute como root. Rode como o seu usuário: ./instalar.sh"
    exit 1
fi

# Executa um comando DENTRO do container (stdin isolado para não travar)
dbx() { distrobox enter "$CONTAINER" -- "$@" </dev/null; }

atualizar_caches() {
    command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" >/dev/null 2>&1
    command -v gtk-update-icon-cache   >/dev/null 2>&1 && gtk-update-icon-cache -f -t "$ICONS_DIR" >/dev/null 2>&1
    if   command -v kbuildsycoca6 >/dev/null 2>&1; then kbuildsycoca6 >/dev/null 2>&1
    elif command -v kbuildsycoca5 >/dev/null 2>&1; then kbuildsycoca5 >/dev/null 2>&1; fi
    return 0
}

# Descobre qual container usar (lido do arquivo salvo, se existir)
[ -f "$CONF_CONTAINER" ] && CONTAINER="$(head -n1 "$CONF_CONTAINER")"

# ---------------------------------------------------------------------
#  DESINSTALAR
# ---------------------------------------------------------------------
if [ "${1:-}" = "--desinstalar" ]; then
    TUDO=0; REM_CONT=0
    for a in "${@:2}"; do
        [ "$a" = "--tudo" ] && TUDO=1
        [ "$a" = "--container" ] && REM_CONT=1
    done
    info "Encerrando o cliente (se estiver rodando)..."
    pkill -f "$APP_DIR/cliente_tox.py" 2>/dev/null || true
    rm -f "$DESKTOP_USER" "$DESKTOP_AUTOSTART"
    for t in 16 22 24 32 48 64 128 256 512; do rm -f "$ICONS_DIR/${t}x${t}/apps/$ID_APP.png"; done
    if [ "$TUDO" -eq 1 ]; then
        rm -rf "$APP_DIR"
        ok "Removido por completo (incluindo dados)."
    else
        rm -rf "$VENV_DIR" "$STATIC_DIR" "$LAUNCHER" "$CONF_CONTAINER" \
               "$APP_DIR"/*.py "$APP_DIR"/*.txt "$APP_DIR"/*.html 2>/dev/null
        ok "Removido. Seus dados Tox foram mantidos em: $APP_DIR/dados_tox_cliente"
    fi
    if [ "$REM_CONT" -eq 1 ] && command -v distrobox >/dev/null 2>&1; then
        info "Removendo o container '$CONTAINER'..."
        distrobox rm --force "$CONTAINER" </dev/null >/dev/null 2>&1 \
            && ok "Container removido." || warn "Não foi possível remover o container."
    else
        info "O container '$CONTAINER' foi mantido (use --container para removê-lo)."
    fi
    atualizar_caches
    exit 0
fi

echo "============================================================"
echo " $NOME_APP - Instalador (distrobox)"
echo "============================================================"

# ---------------------------------------------------------------------
#  1) Arquivos de origem
# ---------------------------------------------------------------------
for f in cliente_tox.py gerar_icone.py requirements.txt xterm.js xterm.css login.html dashboard.html; do
    if [ ! -f "$ORIGEM/$f" ]; then
        erro "Arquivo '$f' não encontrado em $ORIGEM"
        erro "Rode o instalador dentro da pasta que contém todos os arquivos."
        exit 1
    fi
done

# ---------------------------------------------------------------------
#  2) SISTEMA (host): distrobox + podman
#     Só aqui a senha de ROOT é necessária, e só se algo estiver faltando.
# ---------------------------------------------------------------------
info "Verificando distrobox no sistema..."

TEM_DISTROBOX=0; command -v distrobox >/dev/null 2>&1 && TEM_DISTROBOX=1
MOTOR=""
if   command -v podman >/dev/null 2>&1; then MOTOR="podman"
elif command -v docker >/dev/null 2>&1; then MOTOR="docker"; fi

PKGS_ROOT=""
[ "$TEM_DISTROBOX" -eq 0 ] && PKGS_ROOT="distrobox"
if [ -z "$MOTOR" ]; then
    PKGS_ROOT="$PKGS_ROOT podman uidmap passt"
    MOTOR="podman"
fi

# podman rootless precisa de faixa de UIDs subordinados para o usuário
PRECISA_SUBID=0
if [ "$MOTOR" = "podman" ]; then
    grep -q "^$USER:" /etc/subuid 2>/dev/null || PRECISA_SUBID=1
    grep -q "^$USER:" /etc/subgid 2>/dev/null || PRECISA_SUBID=1
fi

if [ -n "$PKGS_ROOT" ] || [ "$PRECISA_SUBID" -eq 1 ]; then
    if ! command -v apt-get >/dev/null 2>&1; then
        erro "Este sistema não usa apt. Instale manualmente (como root): distrobox e podman."
        exit 1
    fi
    if ! command -v su >/dev/null 2>&1; then
        erro "Comando 'su' não encontrado. Peça ao administrador para instalar:$PKGS_ROOT"
        exit 1
    fi

    CMD_ROOT="touch '__FLAG__'; export DEBIAN_FRONTEND=noninteractive; export PATH=/usr/sbin:/sbin:\$PATH; "
    if [ -n "$PKGS_ROOT" ]; then
        CMD_ROOT+="apt-get update -qq; "
        CMD_ROOT+="apt-get install -y $PKGS_ROOT || { rc=1; for p in $PKGS_ROOT; do apt-get install -y \$p || echo \"[AVISO] falhou: \$p\"; done; }; "
    fi
    if [ "$PRECISA_SUBID" -eq 1 ]; then
        CMD_ROOT+="grep -q '^$USER:' /etc/subuid || usermod --add-subuids 100000-165535 '$USER'; "
        CMD_ROOT+="grep -q '^$USER:' /etc/subgid || usermod --add-subgids 100000-165535 '$USER'; "
    fi
    CMD_ROOT+="true"

    echo
    info "Faltando no sistema:${PKGS_ROOT:- (ajuste de UIDs do podman)}"
    info "Será pedida a SENHA DO ROOT. Ela é usada somente nesta etapa."
    FLAG="$(mktemp)"; rm -f "$FLAG"
    CMD_FINAL="${CMD_ROOT//__FLAG__/$FLAG}"
    TENT=0; FEITO=0
    while [ "$TENT" -lt 3 ]; do
        su -l root -c "$CMD_FINAL" && { FEITO=1; break; }
        # se o flag existe, a senha foi aceita (falha foi do apt, não da senha)
        [ -f "$FLAG" ] && break
        TENT=$((TENT+1)); warn "Senha incorreta ($TENT/3)."
    done
    rm -f "$FLAG"
    hash -r
    if ! command -v distrobox >/dev/null 2>&1; then
        erro "distrobox não foi instalado. Verifique a senha de root e a internet."
        exit 1
    fi
    [ "$FEITO" -eq 1 ] || warn "A etapa root terminou com avisos; continuando."
    [ "$MOTOR" = "podman" ] && podman system migrate >/dev/null 2>&1
    ok "distrobox e motor de containers prontos."
else
    ok "distrobox já instalado: a senha de root NÃO é necessária."
fi

# A partir daqui tudo roda como USUÁRIO COMUM (sem root).

# ---------------------------------------------------------------------
#  3) Container Debian (distrobox)
#     - usa um container Debian existente, se houver
#     - senão baixa a imagem e cria com o nome "debian"
# ---------------------------------------------------------------------
info "Procurando container Debian no distrobox..."
LISTA="$(distrobox list --no-color </dev/null 2>/dev/null)"
EXISTE=""
if echo "$LISTA" | awk -F'|' 'NR>1{gsub(/ /,"",$2); print $2}' | grep -qx "$CONTAINER"; then
    EXISTE="$CONTAINER"
else
    # outro container que use imagem debian
    OUTRO="$(echo "$LISTA" | awk -F'|' 'NR>1{n=$2; i=$4; gsub(/ /,"",n); if (i ~ /debian/) {print n; exit}}')"
    [ -n "$OUTRO" ] && EXISTE="$OUTRO"
fi

if [ -n "$EXISTE" ]; then
    CONTAINER="$EXISTE"
    ok "Usando o container existente: $CONTAINER"
else
    info "Nenhum container Debian. Baixando a imagem ($IMAGEM) e criando '$CONTAINER'..."
    if ! distrobox create --name "$CONTAINER" --image "$IMAGEM" --yes </dev/null; then
        erro "Falha ao criar o container (verifique a internet)."
        exit 1
    fi
    ok "Container '$CONTAINER' criado."
fi

info "Iniciando o container (a primeira vez demora um pouco)..."
if ! dbx true; then
    erro "Não foi possível iniciar o container '$CONTAINER'."
    exit 1
fi
ok "Container em execução."

if ! dbx grep -qi '^ID=debian' /etc/os-release; then
    warn "O container '$CONTAINER' não parece ser Debian; seguindo mesmo assim (apt)."
fi

# ---------------------------------------------------------------------
#  4) Dependências DENTRO do container (Python, Tox, bandeja...)
#     O sudo do container é interno: não dá acesso root ao sistema.
# ---------------------------------------------------------------------
info "Verificando pacotes dentro do container..."
PKGS="python3 python3-venv python3-pip python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 libayatana-appindicator3-1 libtoxcore2 iproute2 ca-certificates"
FALTANDO="$(dbx bash -c "for p in $PKGS; do dpkg -s \$p >/dev/null 2>&1 || echo -n \"\$p \"; done")"
if [ -n "${FALTANDO// /}" ]; then
    info "Instalando no container: $FALTANDO"
    dbx sudo env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    if ! dbx sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y $FALTANDO; then
        warn "Falha em lote, tentando um por um..."
        for p in $FALTANDO; do
            dbx sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" >/dev/null 2>&1 \
                || warn "Não foi possível instalar: $p"
        done
    fi
else
    ok "Pacotes do container já instalados."
fi

# libtoxcore: alternativas, caso o nome mude na versão do Debian
if ! dbx bash -c 'ldconfig -p 2>/dev/null | grep -q libtoxcore'; then
    for alt in libtoxcore-dev libtoxcore3 libtoxcore; do
        dbx sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "$alt" >/dev/null 2>&1 && break
    done
    dbx bash -c 'ldconfig -p 2>/dev/null | grep -q libtoxcore' \
        && ok "libtoxcore instalada." \
        || warn "libtoxcore NÃO encontrada no container (apt search toxcore)."
fi

dbx python3 --version >/dev/null 2>&1 || { erro "python3 não encontrado no container."; exit 1; }

# ---------------------------------------------------------------------
#  5) Pasta da aplicação (a HOME é compartilhada com o container)
# ---------------------------------------------------------------------
info "Criando pasta: $APP_DIR"
mkdir -p "$APP_DIR" "$STATIC_DIR" "$APPS_DIR" "$AUTOSTART_DIR"
pkill -f "$APP_DIR/cliente_tox.py" 2>/dev/null || true
dbx pkill -f "$APP_DIR/cliente_tox.py" >/dev/null 2>&1 || true

for f in cliente_tox.py gerar_icone.py requirements.txt login.html dashboard.html; do
    cp -f "$ORIGEM/$f" "$APP_DIR/$f"
done
cp -f "$ORIGEM/xterm.js"  "$STATIC_DIR/xterm.js"
cp -f "$ORIGEM/xterm.css" "$STATIC_DIR/xterm.css"
chmod 755 "$APP_DIR/cliente_tox.py"
printf '%s\n' "$CONTAINER" > "$CONF_CONTAINER"
ok "Arquivos copiados."

# ---------------------------------------------------------------------
#  6) Ambiente virtual + bibliotecas (criado DENTRO do container)
#     --system-site-packages: PyGObject (gi) para o ícone de bandeja.
# ---------------------------------------------------------------------
info "Criando ambiente virtual Python (no container)..."
if [ -e "$VENV_DIR" ] && ! dbx "$VENV_DIR/bin/python3" -c "import sys" >/dev/null 2>&1; then
    warn "Ambiente virtual antigo/incompatível, recriando."
    rm -rf "$VENV_DIR"
fi
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    dbx python3 -m venv --system-site-packages "$VENV_DIR" \
        || { erro "Falha ao criar o venv."; exit 1; }
fi
ok "Ambiente virtual: $VENV_DIR"

info "Instalando bibliotecas Python..."
dbx "$VENV_DIR/bin/python3" -m pip install --upgrade pip >/dev/null 2>&1
if ! dbx "$VENV_DIR/bin/python3" -m pip install -r "$APP_DIR/requirements.txt"; then
    erro "Falha ao instalar as bibliotecas Python."
    exit 1
fi
ok "Bibliotecas instaladas."

if dbx "$VENV_DIR/bin/python3" -c "import gi" >/dev/null 2>&1; then
    ok "PyGObject disponível: bandeja usará AppIndicator (KDE X11/Wayland)."
    TEM_GI=1
else
    warn "PyGObject (gi) indisponível: a bandeja usará o backend padrão do pystray."
    TEM_GI=0
fi

# ---------------------------------------------------------------------
#  7) Logo e ícones
# ---------------------------------------------------------------------
info "Gerando logo e ícones..."
( cd "$APP_DIR" && dbx "$VENV_DIR/bin/python3" gerar_icone.py >/dev/null ) \
    || { erro "Falha ao gerar o logo."; exit 1; }

cat > "$APP_DIR/instalar_icones.py" <<'PYEOF'
import sys
from pathlib import Path
from PIL import Image
static, icons, nome = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
logo = Image.open(static / "logo.png").convert("RGBA")
tray = Image.open(static / "tray.png").convert("RGBA")
for t in (16, 22, 24, 32, 48, 64, 128, 256, 512):
    base = tray if t <= 64 else logo      # tamanhos pequenos: versão simplificada
    img = base.resize((t, t), Image.LANCZOS)
    d = icons / f"{t}x{t}" / "apps"
    d.mkdir(parents=True, exist_ok=True)
    img.save(d / f"{nome}.png", "PNG")
PYEOF
dbx "$VENV_DIR/bin/python3" "$APP_DIR/instalar_icones.py" "$STATIC_DIR" "$ICONS_DIR" "$ID_APP" \
    || { erro "Falha ao instalar os ícones."; exit 1; }
rm -f "$APP_DIR/instalar_icones.py"
ok "Ícones instalados em $ICONS_DIR"

# ---------------------------------------------------------------------
#  8) ATALHOS (só agora, com o container pronto)
#     O atalho inicia o distrobox/imagem Debian e roda o .py lá dentro.
#     - Se o cliente já estiver rodando, apenas abre o painel.
#     - Com --autostart, inicia silenciosamente (só bandeja).
# ---------------------------------------------------------------------
info "Criando launcher..."
mkdir -p "$APP_DIR/dados_tox_cliente"
chmod 700 "$APP_DIR/dados_tox_cliente"

if [ "$TEM_GI" -eq 1 ]; then
    LINHA_BANDEJA='export PYSTRAY_BACKEND="${PYSTRAY_BACKEND:-appindicator}"'
else
    LINHA_BANDEJA='# (sem PyGObject: pystray escolhe o backend)'
fi

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# $NOME_APP - launcher (executa o cliente dentro do distrobox)
APP_DIR="$APP_DIR"
CONTAINER="$CONTAINER"
PORTA=$PORTA
URL="http://127.0.0.1:\$PORTA/"

porta_em_uso() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":\$PORTA "
    else
        (exec 3<>/dev/tcp/127.0.0.1/\$PORTA) 2>/dev/null
    fi
}

if porta_em_uso; then
    # já está rodando: só abre o painel (exceto no autostart)
    [ "\${1:-}" = "--autostart" ] || xdg-open "\$URL" >/dev/null 2>&1
    exit 0
fi

mkdir -p "\$APP_DIR/dados_tox_cliente"
cd "\$APP_DIR" || exit 1

export XDG_RUNTIME_DIR="\${XDG_RUNTIME_DIR:-/run/user/\$(id -u)}"
export DBUS_SESSION_BUS_ADDRESS="\${DBUS_SESSION_BUS_ADDRESS:-unix:path=\$XDG_RUNTIME_DIR/bus}"
$LINHA_BANDEJA

# Inicia o container Debian (se parado) e roda o cliente dentro dele
exec distrobox enter "\$CONTAINER" -- env \\
    PYSTRAY_BACKEND="\${PYSTRAY_BACKEND:-}" \\
    "\$APP_DIR/env/bin/python3" "\$APP_DIR/cliente_tox.py" \\
    >> "\$APP_DIR/dados_tox_cliente/launcher.log" 2>&1 </dev/null
EOF
chmod 755 "$LAUNCHER"
ok "Launcher: $LAUNCHER"

info "Criando atalho do menu..."
cat > "$DESKTOP_USER" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$NOME_APP
GenericName=Acesso Remoto via Tox
Comment=Acesso remoto a servidores via protocolo Tox (container Debian)
Exec=$LAUNCHER
Icon=$ID_APP
Terminal=false
Categories=System;Network;RemoteAccess;Utility;
Keywords=tox;remoto;acesso;servidor;ssh;rrfs;
StartupNotify=false
EOF
chmod 755 "$DESKTOP_USER"
command -v desktop-file-validate >/dev/null 2>&1 && desktop-file-validate "$DESKTOP_USER" 2>&1 | sed 's/^/    /' || true
ok "Atalho: $DESKTOP_USER"

info "Configurando início automático..."
cat > "$DESKTOP_AUTOSTART" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=$NOME_APP
Comment=Inicia o cliente Tox ao entrar na sessão
Exec=$LAUNCHER --autostart
Icon=$ID_APP
Terminal=false
X-KDE-autostart-after=panel
X-KDE-StartupNotify=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=8
Hidden=false
EOF
chmod 644 "$DESKTOP_AUTOSTART"
ok "Autostart: $DESKTOP_AUTOSTART"

atualizar_caches

# ---------------------------------------------------------------------
#  Resumo
# ---------------------------------------------------------------------
echo
echo "============================================================"
echo " INSTALAÇÃO CONCLUÍDA"
echo "============================================================"
echo " Container .... $CONTAINER (distrobox)"
echo " Pasta ........ $APP_DIR"
echo " Ambiente ..... $VENV_DIR (dentro do container)"
echo " Atalho ....... $DESKTOP_USER"
echo " Autostart .... $DESKTOP_AUTOSTART"
echo " Painel ....... http://127.0.0.1:$PORTA/"
echo
echo " Procure por '$NOME_APP' no menu (Sistema/Rede)."
echo " Ele também iniciará sozinho no próximo login."
echo " Log: $APP_DIR/dados_tox_cliente/launcher.log"
echo " Se o ícone antigo continuar aparecendo: saia e entre na sessão."
echo

read -r -p "Iniciar o $NOME_APP agora? [S/n] " RESP
case "${RESP:-S}" in
    n|N) ;;
    *) nohup "$LAUNCHER" --autostart >/dev/null 2>&1 &
       sleep 5; xdg-open "http://127.0.0.1:$PORTA/" >/dev/null 2>&1 || true
       ok "Iniciado." ;;
esac
