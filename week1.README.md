# A팀 1주차 | OWASP IoTGoat 펌웨어 확보와 구조 파악

Raspberry Pi 2용 IoTGoat 이미지에서 Linux 파일시스템을 추출했다. 계정과 웹 서버 설정을 읽고, `/bin/busybox`가 어떤 CPU에서 실행되는지 ELF 헤더와 문자열로 확인했다. 현재 아키텍처와 문자열을 모두 확인한 실행 파일은 과제 기준 3개 중 1개다.

## 1. 분석한 이미지

| 항목 | 실습 기록 |
|---|---|
| 배포본 | OWASP IoTGoat `v1.0`, Raspberry Pi 2용 이미지. 
| 파일 | `IoTGoat-raspberry-pi2.img`, 33,306,530바이트. 
| 환경 | Windows에서 Oracle VirtualBox로 실행한 Ubuntu Desktop |
| 작업 폴더 | `~/firmware-analysis-team-A/week1` |

원본 이미지를 식별하기 위해 `sha256sum`으로 해시를 계산했다. 

```text
320b88ec8bdd7cae9f99669275b3b0f48dfea5284af9d809fa5aa6ec6a792515  IoTGoat-raspberry-pi2.img
```

## 2. 이미지 형식과 파일시스템 추출

`week1` 폴더에서 다음 명령을 사용했다.

```bash
sha256sum IoTGoat-raspberry-pi2.img | tee evidence/sha256.txt
file IoTGoat-raspberry-pi2.img | tee evidence/file.txt
binwalk IoTGoat-raspberry-pi2.img | tee evidence/binwalk.txt
binwalk -e IoTGoat-raspberry-pi2.img
find . -type d -name squashfs-root
```

| 확인한 항목 | 실제 출력과 해석 |
|---|---|
| 디스크 이미지 | `file`에서 `DOS/MBR boot sector`가 나왔다. 첫 번째 파티션의 유형은 `0x0c`, 두 번째는 `0x83`이었다.  |
| 파일시스템 위치 | `binwalk`는 이미지 시작점에서 29,360,128바이트(`0x1C00000`) 떨어진 곳에서 SquashFS를 찾았다. 이 값은 두 번째 파티션의 시작 섹터 57,344에 512바이트를 곱한 값과 일치한다. |
| 파일시스템 형식 | SquashFS 4.0, 리틀 엔디언, XZ 압축. 압축된 크기는 3,946,402바이트이고 inode는 1,333개였다. |
| 추출 결과 | `./_IoTGoat-raspberry-pi2.img.extracted/squashfs-root`가 생성됐다. 최상위에서 `etc`, `bin`, `usr`, `lib`, `sbin`, `www`를 확인했다. |



## 3. 디렉터리 탐색과 주요 파일 5개

아래의 `/etc`, `/bin`, `/usr`는 모두 추출한 펌웨어 안의 경로다. 터미널에서는 `ROOT`에 추출 경로를 저장해 조사했다.

```bash
ROOT="./_IoTGoat-raspberry-pi2.img.extracted/squashfs-root"
ls -1 "$ROOT/etc" | tee evidence/etc-list.txt
ls -1 "$ROOT/etc/config" | tee evidence/config-list.txt
ls -1 "$ROOT/bin" | tee evidence/bin-list.txt
cat "$ROOT/etc/config/uhttpd" | tee evidence/uhttpd-config.txt
cat "$ROOT/etc/passwd" | tee evidence/passwd.txt
```

| 파일 경로 | 종류 | 역할 | 선정 이유 |
|---|---|---|---|
| `/usr/sbin/uhttpd` | 실행 파일 | HTTP·HTTPS 요청을 처리하는 경량 웹 서버다. | 웹 관리 화면에 접속했을 때 들어오는 요청을 이 프로그램에서 추적할 수 있다. |
| `/bin/busybox` | 실행 파일 | 여러 기본 리눅스 명령과 셸 기능을 하나의 파일로 제공한다. | 장치에서 파일을 다루고 명령을 실행할 때 사용하는 기본 도구를 파악할 수 있다. |
| `/etc/shadow` | 계정 인증 정보 파일 | 계정별 비밀번호 해시 또는 잠금 표시와 비밀번호 변경·만료 정보를 저장한다. | `/etc/passwd`의 사용자 이름과 대조해 계정별 비밀번호 필드의 상태와 만료 정책을 확인할 수 있다. |
| `/etc/config/uhttpd` | 설정 파일 | 웹 서버가 요청을 받을 주소·포트와 웹 문서의 위치를 지정한다. | `/usr/sbin/uhttpd`가 어느 포트에서 요청을 받고 어느 디렉터리의 문서를 제공하도록 설정됐는지 확인할 수 있다. |
| `/etc/passwd` | 계정 정보 파일 | 사용자 이름, 사용자 ID(UID), 기본 그룹 ID(GID), 홈 디렉터리, 로그인 셸을 기록한다. | 관리자 권한을 갖는 UID 0 계정을 식별하고, 계정별 로그인 환경을 비교할 수 있다. |

**실습 로그에서 확인한 내용**

- `/bin/busybox`는 크기 394,485바이트, 권한 `-rwxr-xr-x`인 일반 파일이었다. 
- `/etc/config/uhttpd`에는 IPv4·IPv6 모두 HTTP 80번과 HTTPS 443번이 지정돼 있었다. `redirect_https` 값은 `1`, 웹 문서 경로는 `/www`였다. 
- `/etc/passwd`에는 7개 계정이 있었다. `root`(UID 0)와 `iotgoatuser`(UID 1000)는 모두 홈 디렉터리가 `/root`, 로그인 셸이 `/bin/ash`였다.

## 4. BusyBox 실행 파일 분석

```bash
file "$ROOT/bin/busybox" | tee evidence/busybox-file.txt
readelf -h "$ROOT/bin/busybox" | tee evidence/busybox-readelf.txt
strings -a "$ROOT/bin/busybox" | head -n 30 | tee evidence/busybox-strings.txt
```

| 분석 방법 | 관찰 결과 |
|---|---|
| `file` | ARM용 32비트 리틀 엔디언 ELF 실행 파일이다. 동적 링크 방식이며, 로더 경로는 `/lib/ld-musl-armhf.so.1`이다.  |
| `readelf -h` | `Type`은 `EXEC`, `Machine`은 `ARM`, 진입점은 `0x16d18`이다. 프로그램 헤더는 7개, 섹션 헤더는 0개였다. |
| `strings -a` | 처음 30줄에 같은 로더 경로와 `libgcc_s.so.1`, `libc.so`, `memcpy`, `malloc`, `strlen`이 보였다. 이 결과에서 확인한 범위는 바이너리에 들어 있는 라이브러리·함수 이름까지다. |

## 5. 2주차 분석 바이너리 후보 1개

공개된 IoTGoat 펌웨어 분석에서는 `/usr/bin/shellback`을 외부 연결을 받아 셸을 제공하는 백도어 서비스로 소개한다. 

| 분석 항목 | 확인할 내용 |
|---|---|
| 연결 수신 | 어느 주소와 포트에서 연결을 기다리는가? |
| 인증 여부 | 연결한 사용자에게 셸을 제공하기 전에 인증을 요구하는가? |
| 셸 실행 | 연결을 받은 뒤 셸을 실행하는 코드가 있는가? 있다면 어떤 프로그램을 호출하는가? |
| 시작 방식 | 어떤 스크립트가 `shellback`을 시작하는가? 부팅할 때 자동으로 실행되도록 등록돼 있는가? |
