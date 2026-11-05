---
description: 출시 프로파일 보안 점검 — 범위·판정·증거·QA 공유
argument-hint: <소스경로> [대상URL]
---

`checking-release-security` 스킬을 사용한다. 입력은 `$ARGUMENTS`다.
`python <실제플러그인루트>/gxsec.py release <소스경로> --profile release --json`을 실행한다.
URL만 주어졌다고 동적 발사를 하지 않는다. 외부 신뢰 정책·배포 revision·합성 fixture·테스트 계정·실행 범위 승인이 갖춰진 경우에만 --policy와 --execute-dynamic을 추가한다.
준비가 부족하면 가능한 정적 결과와 INCOMPLETE·준비 목록을 전달한다. 정적 중심만 원하는 경우 --profile static-release를 사용한다.
