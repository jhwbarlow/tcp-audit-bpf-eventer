FROM golang:1.17 AS builder
COPY . /tmp/src
RUN apt-get update -yq && \
    apt-get install -yq clang libelf-dev && \
    apt-get clean -yq && \
    cd /tmp && \
    git clone https://github.com/libbpf/libbpf.git && \
    cd /tmp/libbpf/src && \
    CFLAGS="-fPIC" BUILD_STATIC_ONLY="y" DESTDIR="/tmp/libbpf/output" make install && \
    cp -ra /tmp/libbpf/output/usr/include/bpf/* /tmp/src/bpf/include/bpf && \
    cp /tmp/libbpf/output/usr/lib64/libbpf.a /tmp/src/bpf/lib && \    
    cd /tmp/src && \
    clang -g -O2 -c -target bpf -o bpf.o bpf/bpf.c && \
    GOOS=linux GOARCH=amd64 CGO_CFLAGS="-I /tmp/src/bpf/include" CGO_LDFLAGS="/tmp/src/bpf/lib/libbpf.a" \
    go build -buildmode=plugin -trimpath -o /tmp/tcp-audit-bpf-eventer.so && \
    chmod 400 /tmp/tcp-audit-bpf-eventer.so

FROM scratch
COPY --from=builder /tmp/tcp-audit-bpf-eventer.so \
                    /usr/lib/x86_64-linux-gnu/libelf.so.1 \
                    /usr/lib/x86_64-linux-gnu/libelf-0.183.so \
                    /lib/x86_64-linux-gnu/libz.so.1.2.11 \
                    /lib/x86_64-linux-gnu/libz.so.1 \
                    /tmp/
ENTRYPOINT []