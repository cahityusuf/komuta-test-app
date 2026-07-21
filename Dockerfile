FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app .

# Runtime: a REAL image with a shell + common attack tools so the exec / file
# triggers actually reach the kernel. A distroless image has NO binaries, so
# every exec test fails with "executable file not found" — which the harness
# then can't tell apart from a real policy block (bogus "Blocked"). This is a
# deliberate attack-simulation image, NOT a hardened production base.
FROM alpine:3.20
RUN apk add --no-cache \
      bash curl wget socat python3 perl nmap openssh-client \
      busybox-extras coreutils util-linux dcron ca-certificates \
  && case "$(uname -m)" in x86_64) K=amd64;; aarch64) K=arm64;; *) K=amd64;; esac \
  && (wget -qO /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.29.3/bin/linux/${K}/kubectl" \
      && chmod +x /usr/local/bin/kubectl) || true
COPY --from=builder /out/app /app
EXPOSE 8080
# Runs as root so the BASELINE run of each trigger SUCCEEDS ("allowed") — the
# whole point is that a Komuta / KubeArmor block is what flips the verdict to
# "denied". The capability / file / mount triggers need this.
ENTRYPOINT ["/app"]