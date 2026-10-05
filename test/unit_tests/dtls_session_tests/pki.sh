#!/bin/bash
# pki.sh — PKI thử nghiệm cho DTLS chế độ certificate.
#
#   pki.sh <thư-mục> <tên-ECU>...          tạo CA + cert cho từng ECU
#   pki.sh <thư-mục> --negative <tên-ECU>  thêm bộ cert "xấu" cho test âm,
#                                                vào <thư-mục>/negative/<tên-ECU>/
#
# Cấu trúc giống PKI trên xe, thu nhỏ:
#
#   Root CA (10 năm)          — trust anchor, giữ offline; ECU chỉ nhận ca.crt
#     └─ Issuing CA (2 năm)   — ký cert ECU; pathlen 0, không ký được CA khác
#          └─ ECU (90 ngày)   — ECDSA P-256, SAN DNS:<tên-ECU>,
#                               EKU serverAuth + clientAuth (ECU vừa là client vừa là server)
#
# ECU nhận:  <tên>/node.key (600)  <tên>/node.crt (leaf + issuing CA)  ca.crt (root)
#
# CHỈ DÙNG CHO LAB: mọi private key nằm chung một thư mục. Trên xe, Root CA ở
# HSM offline của OEM, Issuing CA ở hạ tầng sản xuất, private key ECU sinh và
# nằm trong HSM của chính ECU (chỉ CSR rời khỏi ECU).
set -euo pipefail

OUT=${1:?usage: $0 <dir> <ecu-name>... | <dir> --negative <ecu-name>}
shift
mkdir -p "$OUT"
cd "$OUT"
umask 077

# Mọi cert phát hành lùi ngày bắt đầu về đây, để ECU có đồng hồ chưa đồng bộ
# (dùng mốc time-floor) không coi cert là "chưa hiệu lực" quá sớm.
START=${PKI_START:-20260901000000Z}
LEAF_DAYS=${PKI_LEAF_DAYS:-90}

curve() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; chmod 600 "$1"; }

# Một cấu hình "openssl ca" nhỏ, chỉ để đặt được ngày bắt đầu/kết thúc tuỳ ý.
ca_conf() {  # <thư-mục-ca>
    mkdir -p "$1/db"; touch "$1/db/index.txt"; [ -f "$1/db/serial" ] || openssl rand -hex 16 > "$1/db/serial"
    cat > "$1/ca.cnf" <<EOF
[ ca ]
default_ca = local
[ local ]
dir = $1
database = \$dir/db/index.txt
serial = \$dir/db/serial
new_certs_dir = \$dir/db
default_md = sha256
policy = any
unique_subject = no
copy_extensions = none
[ any ]
commonName = supplied
[ v3_root ]
basicConstraints = critical, CA:true, pathlen:1
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_issuing ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_ecu ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:\${ENV::PKI_SAN}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_ecu_serveronly ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:\${ENV::PKI_SAN}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
}

# YYYYmmddHHMMSSZ -> giây epoch (rỗng nếu date không hiểu)
epoch_of() { date -u -d "${1:0:4}-${1:4:2}-${1:6:2} ${1:8:2}:${1:10:2}:${1:12:2}" +%s 2>/dev/null; }

# "-days N" của openssl tính từ đồng hồ máy, không từ -startdate: trên máy đang ở
# 1970 (ECU không có RTC) cert sẽ hết hạn trước khi bắt đầu. Đổi N ngày thành ngày kết thúc
# tính từ <start>.
dates_for() {  # <start> <end|days>
    case $2 in
        *Z) echo "-enddate $2" ;;
        *)  local at; at=$(epoch_of "$1") || at=
            if [ -n "$at" ]; then echo "-enddate $(date -u -d "@$((at + $2 * 86400))" +%Y%m%d%H%M%SZ)"; else echo "-days $2"; fi ;;
    esac
}

sign() {  # <ca-dir> <ca-crt> <ca-key> <csr> <out-crt> <ext> <start> <end|days> <san>
    local dates
    dates=$(dates_for "$7" "$8")
    PKI_SAN=${9:-none} openssl ca -batch -config "$1/ca.cnf" -cert "$2" -keyfile "$3" -in "$4" -out "$5" \
        -extensions "$6" -startdate "$7" $dates -notext >/dev/null 2>&1
}

make_root() {  # <dir> <cn>
    mkdir -p "$1"; ca_conf "$PWD/$1"; curve "$1/ca.key"
    openssl req -new -key "$1/ca.key" -subj "/CN=$2" -out "$1/ca.csr"
    PKI_SAN=none openssl ca -batch -selfsign -config "$PWD/$1/ca.cnf" -keyfile "$1/ca.key" -in "$1/ca.csr" \
        -out "$1/ca.crt" -extensions v3_root -startdate "$START" $(dates_for "$START" 3650) -notext >/dev/null 2>&1
}

make_ecu() {  # <issuing-dir> <name> <out-dir> <ext> <start> <end|days>
    mkdir -p "$3"; curve "$3/node.key"
    openssl req -new -key "$3/node.key" -subj "/CN=$2" -out "$3/node.csr"
    sign "$PWD/$1" "$1/ca.crt" "$1/ca.key" "$3/node.csr" "$3/leaf.crt" "$4" "$5" "$6" "$2"
    cat "$3/leaf.crt" "$1/ca.crt" > "$3/node.crt"   # gửi kèm Issuing CA để peer dựng được chain
    rm -f "$3/node.csr" "$3/leaf.crt"
    chmod 644 "$3/node.crt"
}

if [ "${1:-}" = --negative ]; then
    NAME=${2:?thiếu tên ECU}
    [ -f issuing/ca.crt ] || { echo "chưa có PKI ở $OUT — chạy $0 $OUT <tên> trước" >&2; exit 1; }
    N=negative/$NAME
    mkdir -p "$N"
    # CA của kẻ tấn công: dựng một lần, dùng chung cho mọi ECU
    if [ ! -f negative/rogue-issuing/ca.crt ]; then
        make_root negative/rogue-root "Rogue Root CA"
        mkdir -p negative/rogue-issuing; ca_conf "$PWD/negative/rogue-issuing"; curve negative/rogue-issuing/ca.key
        openssl req -new -key negative/rogue-issuing/ca.key -subj "/CN=Rogue Issuing CA" -out negative/rogue-issuing/ca.csr
        sign "$PWD/negative/rogue-root" negative/rogue-root/ca.crt negative/rogue-root/ca.key \
            negative/rogue-issuing/ca.csr negative/rogue-issuing/ca.crt v3_issuing "$START" 730
    fi
    # 1. Đúng tên, nhưng do CA khác ký
    make_ecu negative/rogue-issuing "$NAME" "$N/rogue" v3_ecu "$START" "$LEAF_DAYS"
    # 2. Đúng CA, đúng tên, đã hết hạn trước time-floor (2026-10-01)
    make_ecu issuing "$NAME" "$N/expired" v3_ecu 20260101000000Z 20260601000000Z
    # 3. Đúng CA, đúng tên, chưa đến ngày hiệu lực
    make_ecu issuing "$NAME" "$N/future" v3_ecu 20300101000000Z 20300401000000Z
    # 4. Đúng CA, hợp lệ, nhưng là cert của một ECU khác
    make_ecu issuing "camera.ecu.lab" "$N/othername" v3_ecu "$START" "$LEAF_DAYS"
    # 5. Đúng CA, đúng tên, nhưng chỉ được làm server (thiếu clientAuth)
    make_ecu issuing "$NAME" "$N/serveronly" v3_ecu_serveronly "$START" "$LEAF_DAYS"
    cp negative/rogue-root/ca.crt negative/rogue-ca.crt
    echo "negative/$NAME: rogue expired future othername serveronly"
    exit 0
fi

[ $# -ge 1 ] || { echo "cần ít nhất một tên ECU" >&2; exit 1; }
AT=$(epoch_of "$START") && [ -n "$AT" ] && VERIFY_AT="-attime $((AT + 60))" || VERIFY_AT=-no_check_time
if [ ! -f root/ca.crt ]; then
    make_root root "Lab Vehicle Root CA"
    mkdir -p issuing; ca_conf "$PWD/issuing"; curve issuing/ca.key
    openssl req -new -key issuing/ca.key -subj "/CN=Lab ECU Issuing CA" -out issuing/ca.csr
    sign "$PWD/root" root/ca.crt root/ca.key issuing/ca.csr issuing/ca.crt v3_issuing "$START" 730
    cp root/ca.crt ca.crt; chmod 644 ca.crt root/ca.crt issuing/ca.crt
fi
for NAME in "$@"; do
    make_ecu issuing "$NAME" "ecu/$NAME" v3_ecu "$START" "$LEAF_DAYS"
    # Kiểm tra chain + purpose tại ngày bắt đầu của PKI, không theo đồng hồ máy:
    # PKI có thể được phát hành trước cho thời điểm sau (hoặc máy đang ở 1970).
    openssl verify $VERIFY_AT -CAfile ca.crt -untrusted issuing/ca.crt -purpose sslserver "ecu/$NAME/node.crt" >/dev/null \
        || { echo "cert $NAME không verify được" >&2; exit 1; }
    echo "ecu/$NAME: $(openssl x509 -in "ecu/$NAME/node.crt" -noout -subject -ext subjectAltName 2>/dev/null | tr '\n' ' ')"
done
