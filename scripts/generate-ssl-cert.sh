#!/bin/bash

# 生成自签名 SSL 证书的脚本
# 用于 Nginx HTTPS 配置

CERT_DIR="./config/ssl"
mkdir -p "$CERT_DIR"

# 生成私钥
openssl genrsa -out "$CERT_DIR/key.pem" 2048

# 生成证书签名请求
openssl req -new -key "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.csr" \
    -subj "/C=CN/ST=State/L=City/O=Organization/CN=192.168.30.127"

# 生成自签名证书（有效期 365 天）
openssl x509 -req -days 365 -in "$CERT_DIR/cert.csr" -signkey "$CERT_DIR/key.pem" \
    -out "$CERT_DIR/cert.pem" -extensions v3_req \
    -extfile <(echo "[v3_req]"; echo "subjectAltName=IP:192.168.30.127")

# 清理临时文件
rm "$CERT_DIR/cert.csr"

echo "SSL 证书已生成在 $CERT_DIR 目录"
echo "证书文件: $CERT_DIR/cert.pem"
echo "私钥文件: $CERT_DIR/key.pem"

