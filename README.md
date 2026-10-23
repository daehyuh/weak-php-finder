# weak-php-finder

PHP2Shell(CVE-2026-109618, CVE-2026-109619) 대응을 위한 **버전 및 운영 증빙 기반 점검 스크립트**입니다.

서브도메인 목록과 관리자가 확인한 PHP 인벤토리를 대조하고, 조치가 필요한 항목과 추가 확인이 필요한 항목을 구분합니다. Python 표준 라이브러리만 사용하며 외부 서버에 요청을 보내지 않습니다.

## 빠른 실행

Python 3.10 이상에서 별도 패키지 설치 없이 실행합니다.

```sh
git clone https://github.com/daehyuh/weak-php-finder.git
cd weak-php-finder
python scanner.py --hosts examples/hosts.txt --inventory examples/inventory.csv --out reports/result.csv --json-out reports/result.json
```

예시의 `example.test`는 가상 도메인입니다. 학교의 실제 도메인, IP, 권고문과 점검 결과는 이 저장소에 포함하지 않았습니다.

예시 결과:

| 호스트 | 판정 |
| --- | --- |
| archive.example.test | NOT_APPLICABLE |
| library.example.test | PATCHED_VERSION |
| portal.example.test | ACTION |
| shop.example.test | REVIEW |

## 입력

`--hosts` 파일에는 호스트 이름을 한 줄에 하나씩 넣습니다. 공백 줄과 `#`으로 시작하는 주석은 무시하고 대소문자와 중복을 정리합니다. URL, 경로, 포트와 IP 리터럴은 받지 않습니다.

`--inventory`는 다음 열이 있는 UTF-8 CSV입니다. 각 서비스의 운영 담당자에게 확인한 정보를 사용합니다.

| 열 | 내용 |
| --- | --- |
| `host` | 호스트 이름 |
| `php_state` | PHP 사용 여부: `yes`, `no`, `unknown` |
| `php_version` | 실제 실행 환경의 정확한 `major.minor.patch` 버전 |
| `evidence` | 패키지 확인 기록, 배포 기록, 담당자 확인 등 추적 가능한 근거 |
| `vendor_patch_id` | 공급업체 백포트가 적용됐다는 경우 해당 공지나 패키지 ID |

호스트 목록에는 있지만 인벤토리에 없는 항목은 `REVIEW`입니다. PHP를 사용하지 않는다는 기록도 근거가 없으면 비적용으로 확정하지 않습니다. `php_state=no`와 PHP 버전이 동시에 입력되는 모순도 검토 대상으로 남깁니다.

## 판정 기준

공식 보안 공지의 수정 버전을 기준으로 비교합니다. 기준일은 2026-10-21이며 이후 공식 공지의 변경을 반영하려면 `scanner.py`의 `FIXED`와 출처를 검토해야 합니다.

| 계열 | 수정 버전 |
| --- | --- |
| PHP 8.5 | 8.5.12 이상 |
| PHP 8.4 | 8.4.27 이상 |
| PHP 8.3 | 8.3.36 이상 |
| PHP 8.2 | 8.2.35 이상 |

| 상태 | 의미 |
| --- | --- |
| `ACTION` | 공식 수정 버전보다 낮거나, 공급업체 패치 근거가 없는 지원 종료 분기. 업데이트 또는 추가 조치 필요 |
| `PATCHED_VERSION` | 인벤토리 버전이 해당 계열의 수정 기준 이상. 실제 배포 상태도 확인 필요 |
| `NOT_APPLICABLE` | PHP를 사용하지 않는다는 운영 근거가 입력됨 |
| `VENDOR_REVIEW` | 백포트 패치가 주장됨. 공급업체 공지와 설치된 빌드를 따로 대조해야 함 |
| `REVIEW` | 근거, 버전, PHP 사용 여부가 없거나 모순됨. 또는 지원하지 않는 분기나 버전 형식 |

## 결과와 해석

CSV에는 호스트, 상태, 판정 이유와 입력된 근거가 들어갑니다. CSV로 내보낼 때 수식으로 실행될 수 있는 문자열은 앞에 작은따옴표를 붙입니다. JSON은 원문 값과 함께 생성 시각, 기준일, 공식 출처, 상태별 건수와 입력 파일 SHA-256을 기록합니다.

**이 도구는 RCE 페이로드를 전송하거나 실제 악용 가능성을 입증하지 않습니다.** HTTP 헤더에 PHP 표시가 없는 것만으로 PHP가 없다고 판단하지도 않습니다. 버전 인벤토리의 정확성, 범위의 완전성, 공급업체 패치와 실제 배포 기록을 검토해야 최종 판단을 내릴 수 있습니다. `PATCHED_VERSION`은 해당 취약점의 버전 조건에 관한 결과이며 시스템 전체가 안전하다는 뜻은 아닙니다.

도메인 발견 수와 취약점 검증 완료 수를 같은 값으로 보고하지 마세요. 이 저장소는 실제 기관 396개 자산을 검사했다는 결과를 제공하지 않습니다.

## 테스트

```sh
python -m unittest discover -s tests -v
```

외부 시스템에 접속하지 않고 네 개 버전 분기의 수정 전후 경계, 모순된 입력, 중복과 잘못된 호스트, CSV 및 JSON 출력, 입력 파일 덮어쓰기 방지를 확인합니다.

## 공식 출처

- [PHP 보안 공지](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
