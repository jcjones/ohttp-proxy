#!/bin/bash
SCRIPT_DIR="$(dirname "$(readlink -f "${0}")")"
cd "${SCRIPT_DIR}" || exit 1

setup_mkcert() {
	if [ ! -d .mkcert ]; then
		git clone https://github.com/FiloSottile/mkcert.git .mkcert
	fi
	pushd .mkcert >/dev/null || exit 1
	go build
	popd >/dev/null || exit 1

	if [ -r .certs/gateway.key.pem ] && \
	   [ -r .certs/relay-client.key.pem ] && \
	   [ -r .certs/relay-web.key.pem ] && \
	   [ -r .certs/ca.cert.pem ]; then
		return
	fi

	mkdir .certs || exit 1

	.mkcert/mkcert -ecdsa \
		-key-file .certs/gateway.key.pem \
		-cert-file .certs/gateway.cert.pem \
		gateway 127.0.0.1 localhost

	cp "$(.mkcert/mkcert -CAROOT)/rootCA.pem" .certs/ca.cert.pem
}

missing() {
	echo "Missing: ${*}"
	exit 255
}

hash go || missing "Golang's go"
hash git || missing "git"
hash docker || missing "Docker"

setup_mkcert


if [ ! -d .privacy-gateway-server-go ]; then
	git clone https://github.com/cloudflare/privacy-gateway-server-go.git .privacy-gateway-server-go
fi

pushd .privacy-gateway-server-go >/dev/null || exit 1
docker build . -t ohttp-gateway:latest
popd >/dev/null || exit 1


echo "Starting gateway on https://localhost:4567/gateway with \
	OHTTP configuration at https://localhost:4567/ohttp-configs"

set -x
docker run --rm --name ohttp-gateway \
	-v "$(pwd)/.certs:/config" \
	-p 4567:4567 \
	-e PORT=4567 \
	-e SSL_CERT_FILE=/config/ca.cert.pem \
	-e CERT=/config/gateway.cert.pem \
	-e KEY=/config/gateway.key.pem \
	ohttp-gateway:latest



