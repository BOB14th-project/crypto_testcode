# Crypto Testcode

## 개요
이 저장소는 대표적인 비양자(post-quantum 이전) 암호 라이브러리에 대한 적합성 및 회귀 테스트를 모아둔 프로젝트입니다. 목표는 고전 알고리즘, 취약한 파라미터 선택, 그리고 향후 양자 내성 전환을 방해할 수 있는 다운그레이드 동작을 조기에 식별하는 것입니다. 각 테스트 스위트는 특정 제공자나 API 표면을 중심으로, 대칭키 암호화, 비대칭 키 교환, 전자서명, 해시, 메시지 인증, 키 파생 과정을 검증합니다.

## 저장소 구조
- `tests/ApiCall/` – 언어/라이브러리별 API 호출 하네스. 모든 라이브러리는 `symmetric`, `PublicKey`, `signature`, `HashKdf`, `entropy`, `protocol` 여섯 개 케이스 디렉터리를 공통적으로 사용합니다. 현재 커버리지는:
  - `openssl`, `GnuTLS`, `NSS`, `boringSSL`, `mbedTLS`, `wolfSSL`
  - `PyCryptodome`, `libsodium`
  - `JavaJca`, `JavaJniBridge` 등 Java 공급자/브리지 계층
  - `AfAlg`, `cryptodev`와 같은 커널/OS 인터페이스
- `tests/CustomImpl/` – 직접 구현한 고전 암호 알고리즘 레퍼런스 및 취약 시나리오 실험 코드
- `tests/NeedCliInput/` – CLI 입력이 필요한 상호작용형 예제 (현재 OpenSSL 카테고리 구조와 동일)
- `tests/NeedGuiInput/` – GUI 상호작용이 필요한 데모(프레임워크별 하위 구조 권장)

## 테스트 중점 영역
- **대칭키 암호** – 블록 모드(CBC, CTR), AEAD(GCM, ChaCha20-Poly1305), 패딩, IV/논스 처리, 스트림 크기 경계값을 검증합니다.
- **공개키 알고리즘** – RSA, ECDH, X25519, FFDHE 등 키 교환 흐름과 키 생성, 직렬화(PEM/DER)를 검사합니다.
- **전자서명** – RSA-PSS, ECDSA, Ed25519를 포함하여 취약한 해시, 줄어든 모듈러 길이를 노리는 부정 테스트를 수행합니다.
- **해시 & KDF** – SHA-2/3, BLAKE2, HMAC, PBKDF2, HKDF, scrypt 등과 구식/저강도 파라미터를 점검합니다.
- **엔트로피 소스** – 라이브러리 RNG가 안전한 엔트로피 공급원을 사용하고 오류 경로를 올바르게 처리하는지 확인합니다.
- **프로토콜 동작** – PQ 옵션 부재 시 TLS 등 핸드셰이크에서 발생할 수 있는 비안전 폴백이나 다운그레이드를 탐지합니다.

## 시작하기
1. 대상 라이브러리 또는 언어에 필요한 의존성을 설치합니다(세부 사항은 해당 하위 디렉터리 참고).
2. 해당 디렉터리에서 하네스를 실행합니다(예: `tests/ApiCall/openssl/`).
3. 출력 결과를 확인하고 비양자내성에 부합하지 않는 기본값이나 파라미터 경고를 검토합니다.

## 빌드 아티팩트
- C++ 예제는 `./scripts/linux_build_all.sh` (기본 Release 빌드) 또는 직접 `cmake -S . -B build/cmake && cmake --build build/cmake` 명령을 실행하면 `build/bin/` 아래에 실행 파일이 생성됩니다. Windows에서는 Git Bash에서 `.sh` 스크립트를 사용하거나, `scripts\windows_build_all.bat Debug` 와 같이 배치 스크립트를 사용해 구성을 지정할 수 있습니다.
- 자바 예제 역시 `./scripts/linux_build_all.sh`/`./scripts/linux_build_java.sh` 또는 Windows 배치 스크립트(`scripts\windows_build_all.bat`, `scripts\windows_build_java.bat`)로 `build/java/`에 컴파일 결과(`.class`)가 저장됩니다.
- CMake 설정 시 `tests/**` 아래의 모든 C/C++ 데모가 자동으로 타깃에 추가되며, GnuTLS·NSS·libsodium 등 외부 라이브러리가 없으면 해당 타깃은 메시지와 함께 빌드에서 자동으로 제외됩니다.
