# p3 — 계층형 접근 제어 웹 프록시

Rust로 작성한 **초고속·저부하** 웹 프록시입니다. 접속 IP(개인) → 부서 → 전체의
계층 구조로 도메인 접근을 허용/거부합니다.

- **비동기 I/O** (tokio) — 연결당 스레드 없이 수만 동시 연결 처리
- **무할당 핫패스** — 도메인 매칭은 라벨 수에 비례하는 해시 조회(O(labels)), 정규식 없음
- **무잠금 정책 조회** — 설정은 시작 시 1회 컴파일되어 불변 `Arc`로 공유
- **세 가지 동작 모드** — 포워드 / 투명(transparent) / MITM

## 정책 모델

요청 `(클라이언트 IP, 도메인)`마다 아래 **우선순위 순서**로 판정합니다.

| 순위 | 레벨 | 매칭 기준 |
|------|------|-----------|
| 1 | `[[individuals]]` | 클라이언트 IP가 정확히 일치 |
| 2 | `[[departments]]` | 클라이언트 IP가 속한 CIDR (최장 접두사 우선) |
| 3 | `[global]` | 모든 클라이언트 |
| 4 | `server.default_action` | 위 어느 레벨도 결정하지 못한 경우 |

- 각 레벨 **안에서는 `deny`를 `allow`보다 먼저** 검사합니다(안전 우선).
- **먼저 결정을 내리는 레벨이 승리**합니다. 예: 부서가 `youtube.com`을 거부해도
  개인 레벨에서 허용하면 그 사용자만 허용됩니다.
- 어느 레벨도 매칭되지 않으면 `default_action`을 적용합니다.

### 도메인 패턴

| 패턴 | 매칭 대상 |
|------|-----------|
| `*` | 모든 도메인 |
| `example.com` | `example.com` **및 모든 하위 도메인** |
| `*.example.com` | 하위 도메인만 (apex 제외) |

매칭은 대소문자를 무시하고 포트를 제거합니다.

## 빌드

```bash
cargo build --release
# 바이너리: target/release/p3
```

## 실행

```bash
# 기본값: 현재 디렉터리의 config.toml
./target/release/p3 [config.toml]

# 로그 레벨 조정 (허용은 debug, 거부는 info로 기록)
RUST_LOG=info ./target/release/p3 config.toml
RUST_LOG=debug ./target/release/p3 config.toml   # 모든 판정 기록
```

`config.example.toml`을 복사해 시작하세요.

```bash
cp config.example.toml config.toml
```

## 모드별 설정

### 1. 포워드 프록시 (`mode = "forward"`)

클라이언트의 프록시 설정에 `http://<서버>:8080`을 지정합니다.

- **HTTP**: 요청의 호스트로 필터링 후 중계
- **HTTPS**: `CONNECT`의 대상 호스트로 필터링 후 **복호화 없이** TCP 터널링

```bash
curl -x http://proxy:8080 https://example.com/
```

### 2. 투명 프록시 (`mode = "transparent"`, Linux 전용)

클라이언트 설정 없이 방화벽에서 트래픽을 리다이렉트합니다. 원 목적지는
`SO_ORIGINAL_DST`로, 호스트명은 TLS SNI(443) / HTTP `Host`(80)로 얻어 필터링하며
복호화하지 않습니다.

예시 iptables (프록시를 8080에서 수신하도록 설정한 경우):

```bash
# 게이트웨이에서 통과 트래픽을 프록시로 전환
iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080
```

### 3. MITM 프록시 (`mode = "mitm"`)

TLS를 종단하여 전체 URL까지 검사합니다. 클라이언트 신뢰 저장소에 설치할 CA가
필요합니다.

CA 생성 예시:

```bash
mkdir -p ca
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout ca/ca.key -out ca/ca.crt \
  -subj "/CN=p3 Proxy CA" \
  -addext "basicConstraints=critical,CA:TRUE"
# ca/ca.crt 를 모든 클라이언트의 신뢰 CA로 배포
```

설정:

```toml
[server]
mode = "mitm"
listen = "0.0.0.0:8080"
default_action = "deny"

[mitm]
ca_cert = "ca/ca.crt"
ca_key  = "ca/ca.key"
# (선택) 사내 CA 등 업스트림 신뢰에 추가할 루트 인증서 PEM
# extra_upstream_ca = "ca/corp-root.crt"
```

호스트별 리프 인증서는 요청 시 생성되어 메모리에 캐시됩니다. 업스트림 연결은
기본적으로 공개 루트 집합(webpki-roots)을 신뢰하며, 사내 CA가 서명한 내부
서비스는 `extra_upstream_ca`로 추가 신뢰할 수 있습니다.

## 설정 예시 (요약)

```toml
[server]
mode = "forward"
listen = "0.0.0.0:8080"
default_action = "deny"

[global]
allow = ["*"]
deny  = ["*.malware.test", "ads.doubleclick.net"]

[[departments]]
name  = "sales"
cidrs = ["192.168.10.0/24", "10.1.0.0/16"]
deny  = ["youtube.com", "facebook.com"]

[[departments]]
name  = "engineering"
cidrs = ["192.168.20.0/24"]
allow = ["github.com", "*.rust-lang.org"]

[[individuals]]
ip    = "192.168.10.55"   # 영업팀장: 부서 거부를 뚫고 유튜브 허용
allow = ["youtube.com"]
```

전체 옵션은 `config.example.toml` 참고.

## 설정 변경 반영

설정은 시작 시에만 읽습니다. 규칙을 바꾸려면 프로세스를 재시작하세요.

## 테스트

```bash
cargo test
```

도메인 매칭, CIDR 최장 접두사, 계층 우선순위, SNI 파서에 대한 단위 테스트가
포함되어 있습니다.

## 구조

```
src/
  main.rs            진입점: 설정 로드, 모드 디스패치, 종료 처리
  config.rs          TOML 스키마 + 로딩/검증
  policy.rs          도메인 매칭(DomainSet) + 레벨별 deny→allow 판정
  ipmap.rs           CIDR → 부서 (최장 접두사 매칭)
  resolver.rs        계층 정책 엔진 (개인→부서→전체→기본값)
  http1.rs           스트리밍 HTTP/1.x 헤드/바디 처리(Content-Length/chunked/close)
  tls/sni.rs         TLS ClientHello SNI 추출
  tls/ca.rs          MITM용 로컬 CA·호스트별 리프 인증서 발급/캐시
  tls/mod.rs         업스트림 TLS 클라이언트 설정
  proxy/forward.rs   포워드 프록시 (HTTP + CONNECT)
  proxy/transparent.rs 투명 프록시 (SO_ORIGINAL_DST + SNI/Host)
  proxy/mitm.rs      MITM 프록시 (TLS 종단 + 재암호화 중계)
```

## 라이선스

MIT
