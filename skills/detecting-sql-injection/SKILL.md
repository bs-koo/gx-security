---
name: detecting-sql-injection
description: >-
  SQIsoft 웹 애플리케이션에서 SQL Injection(SQLi) 취약점을 검사한다.
  사용자 입력이 SQL 쿼리에 파라미터 바인딩 없이 문자열 연결로 삽입되는 패턴을 탐지한다.
  프로젝트 스택(Spring Boot 모던 / JSP·Servlet 레거시)을 자동 감지하여 스택별 Semgrep 룰로
  1차 탐지하고, AI가 바인딩 방식과 입력 출처를 컨텍스트로 검증한다.
  JSP scriptlet Statement 문자열 연결, MyBatis Mapper XML ${param}(vs 안전한 #{param}),
  Spring JPA @Query 문자열 연결, JdbcTemplate 문자열 연결, 정렬·검색 컬럼명 동적 삽입 등을 찾는다.
domain: cybersecurity
subdomain: web-application-security
tags: [sql-injection, sqli, cwe-89, owasp-a03, mybatis, jpa, jdbc, spring, jsp, servlet, sqisoft]
cwe: [CWE-89]
owasp: [A03:2021-Injection]
stacks: [spring-modern, jsp-legacy]
version: "0.2.1"
author: sqisoft-security
license: Proprietary
---

# SQL Injection 취약점 검사

## When to Use

다음 중 하나라도 해당하면 이 스킬을 실행한다.

- SQIsoft 프로젝트(`sqisoft-sef-2026`, `Gseed_Web_Renew`)의 **DB 조회·수정·삭제 기능**(검색, 게시판 CRUD, 로그인, 관리자 필터)을 점검할 때
- MyBatis Mapper XML에서 `${param}` 사용 의심 시 (안전한 `#{param}` 와 구분)
- JSP scriptlet에서 `Statement` + 문자열 연결 패턴이 보일 때
- JPA `createQuery`·`@Query`에서 문자열 연결로 JPQL/SQL 조립 의심 시
- 검색 정렬 컬럼명·ORDER BY 절을 사용자 입력으로 동적 구성할 때
- 보안 코드 리뷰·출시 전 점검에서 SQL Injection 방어 적용 여부를 확인할 때

**이 스킬을 쓰지 않을 때:** XSS·CSRF 등 다른 취약점 클래스(→ 해당 스킬 사용). 사용자 입력이 전혀 없는 배치 쿼리·하드코딩 SQL.

## Prerequisites

- 대상 프로젝트 소스에 대한 읽기 접근
- (선택, 권장) `semgrep` 설치 — 없으면 `scripts/scan_sqli.py`가 grep 폴백으로 동작
- 스택 판별 참고: `references/stack-patterns.md`

## Workflow

### 0단계 — 스택 자동 감지

대상 경로의 루트 신호를 확인해 스택을 판별한다. 한 리포에 둘이 섞이면 디렉토리별로 나눠 판별한다.

| 스택 | 감지 신호 | 적용 룰 |
|---|---|---|
| `spring-modern` | `build.gradle.kts`/`settings.gradle*`, `src/main/java/**`, `@Repository`/`@Query` | `rules/sqli.yml`의 spring 룰 |
| `jsp-legacy` | `**/WEB-INF/web.xml`, `*.jsp`, `pom.xml`, MyBatis XML in `sqlmap/` | `rules/sqli.yml`의 jsp 룰 |

```bash
# 스택 신호 빠른 확인
ls "$TARGET"/build.gradle.kts "$TARGET"/settings.gradle.kts 2>/dev/null   # → spring-modern
find "$TARGET" -name web.xml -path '*WEB-INF*' -o -name '*.jsp' | head    # → jsp-legacy
```

### 1단계 — 스캐너 1차 탐지 (재현 가능)

```bash
python skills/detecting-sql-injection/scripts/scan_sqli.py "$TARGET" --json
```

스크립트는 스택을 감지해 알맞은 Semgrep 룰을 돌리고, Semgrep이 없으면 grep 폴백으로 후보를 잡는다. 출력은 `{file, line, rule_id, stack, snippet}` 목록.

### 2단계 — AI 컨텍스트 검증 (핵심)

스캐너 후보는 **출발점일 뿐**이다. 각 후보를 다음 기준으로 직접 검증한다.

**jsp-legacy 검증 포인트**

1. `Statement` + 문자열 연결 — `getParameter()` 등 사용자 입력이 SQL 문자열에 직접 포함되면 **확정 취약**. `PreparedStatement`로 전환 여부 확인.
2. MyBatis Mapper XML `${param}` — `${}` 구문은 값을 따옴표 없이 SQL에 삽입(SQL 조각 치환). 사용자 입력 출처이면 취약. `#{param}`(PreparedStatement 바인딩)이면 안전.
   - ORDER BY·컬럼명 동적 삽입 목적의 `${}` — 값을 허용 목록(allowlist)으로 검증했는지 확인. 없으면 취약.
3. `iBatis/iBATIS` 레거시 — `#value#`(안전), `$value$`(취약).

**spring-modern 검증 포인트**

1. JPA `EntityManager.createQuery(String)` + 문자열 연결 — JPQL도 문자열 연결 시 JPQL Injection 가능. 파라미터 바인딩(`setParameter`) 여부 확인.
2. `@Query(value="... WHERE name='" + param + "'")` — 애노테이션 값이 런타임 문자열이 아니라 컴파일 타임 상수이므로 직접 주입은 불가하나, native query에서 동적 조립 시 위험.
3. `JdbcTemplate.query(String sql, ...)` — SQL 문자열이 `"SELECT ... WHERE x='" + input + "'"` 형태이면 취약. `?` 플레이스홀더 사용이면 안전.
4. MyBatis Mapper XML `${}` — Spring-modern도 MyBatis 혼용 시 동일하게 점검.
5. 정렬 컬럼명(`sortColumn`, `orderBy`) 동적 삽입 — 허용 목록 없는 `ORDER BY ${sortColumn}`은 취약.

**공통 — 누락 보강 (스캐너가 못 잡는 것)**

- 저장 프로시저 호출 시 사용자 입력을 SQL 파편으로 전달하는 경우
- 에러 메시지에 SQL 구문이 노출(Error-based SQLi 피해 확대) — DB 예외를 그대로 응답에 반환하는지 확인
- Second-order SQLi: 사용자 입력이 DB에 저장된 후, 다른 쿼리에서 이 값을 다시 SQL에 연결하는 패턴

### 3단계 — 사업부 표준 리포트

확정된 항목만 아래 양식으로 출력한다. 스캐너 후보 중 검증에서 탈락한 것은 "오탐 제외"에 간단히 남긴다.

## Output Format

```markdown
# SQL Injection 취약점 점검 리포트
- 대상: <프로젝트/경로>   | 감지 스택: <spring-modern | jsp-legacy | mixed>
- 스캐너: <semgrep vX.Y | grep-fallback>   | 점검일: <YYYY-MM-DD>

## 요약
- 확정 취약: N건 (Critical n / High n / Medium n)
- 의도된 예외: M건   | 오탐 제외: K건

## 확정 취약점

### [Critical] SQL Injection — MyBatis ${} 사용자 입력 직접 삽입 — BoardMapper.xml:34
- 스택 / 위치: jsp-legacy / BoardMapper.xml:34
- **① 취약한 점(What)**: MyBatis Mapper XML에서 `${keyword}` 구문으로 사용자 검색어를 SQL에 직접 삽입. 따옴표·이스케이프 없이 SQL 조각으로 치환됨.
- **② 취약한 이유(Why)**: MyBatis `${}` 는 PreparedStatement 파라미터 바인딩이 아닌 문자열 치환이다. 입력값이 그대로 SQL 파서에 전달되므로 공격자가 SQL 구문을 조작하여 인증 우회, 데이터 전체 추출(UNION 기반), 데이터 삭제·수정이 가능하다.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  검색어 파라미터에 아래를 입력:
  ```
  ' OR '1'='1
  ```
  쿼리가 `WHERE keyword LIKE '%' OR '1'='1%'` 로 변형되어 전체 데이터 반환.
  UNION 기반 데이터 추출 개념:
  ```
  ' UNION SELECT username, password, NULL FROM users--
  ```
  (컬럼 수는 원본 쿼리에 맞춰 조정)
- **④ 해결방법(Fix)**: `${}` → `#{}` 로 교체. MyBatis `#{}` 는 PreparedStatement `?` 바인딩을 사용함.
  ```xml
  <!-- Before (취약) -->
  <select id="searchBoards" resultType="BoardVo">
      SELECT * FROM board WHERE title LIKE '%${keyword}%'
  </select>

  <!-- After (안전) -->
  <select id="searchBoards" resultType="BoardVo">
      SELECT * FROM board WHERE title LIKE CONCAT('%', #{keyword}, '%')
  </select>
  ```
- 참조: CWE-89, OWASP A03:2021

### [High] SQL Injection — ORDER BY 컬럼명 동적 삽입 허용목록 없음 — BoardMapper.xml:58
- 스택 / 위치: spring-modern / BoardMapper.xml:58
- **① 취약한 점(What)**: `ORDER BY ${sortColumn}` — 정렬 컬럼명을 사용자 입력으로 받아 허용 목록 검증 없이 삽입.
- **② 취약한 이유(Why)**: 컬럼명은 `#{}` 바인딩 불가(SQL 식별자). `${}` 사용 시 공격자가 임의 SQL 표현식 삽입 가능. Error-based·Time-based SQLi 경로가 열림.
- **③ 뚫리는 방법(How · 개념 PoC)**:
  ```
  sortColumn = (SELECT SLEEP(5))   ← Time-based: 5초 지연 확인 시 취약 확정
  sortColumn = (SELECT CASE WHEN (1=1) THEN title ELSE price END)
  ```
- **④ 해결방법(Fix)**: 서비스 레이어에서 허용 컬럼명 허용 목록 검증 후 전달.
  ```java
  // 서비스 레이어 허용 목록 검증
  private static final Set<String> ALLOWED_SORT_COLUMNS =
      Set.of("title", "created_at", "view_count");

  public List<BoardVo> search(String keyword, String sortColumn) {
      if (!ALLOWED_SORT_COLUMNS.contains(sortColumn)) {
          sortColumn = "created_at";  // 기본값 사용
      }
      return boardMapper.searchBoards(keyword, sortColumn);
  }
  ```
- 참조: CWE-89, OWASP A03:2021

## 의도된 예외 (확인 필요)
- [Info] MyBatis `${schema}` — 스키마명을 환경설정(application.yml)에서 주입. 사용자 입력 아님 → 허용 가능. 단 설정값 검증 권장.

## 오탐 제외
- BoardMapper.xml:12 `#{keyword}` — PreparedStatement 바인딩, 안전
- UserMapper.xml:8 `#{userId}` — PreparedStatement 바인딩, 안전
```

## Verification (검사 자체의 신뢰성 확인)

- [ ] 스택 감지 결과가 실제 프로젝트와 일치하는가(MyBatis XML 위치 포함)
- [ ] 모든 MyBatis Mapper XML의 `${}` 를 `#{}` 와 구분해 확인했는가
- [ ] `${}` 발견 시 입력 출처(사용자 파라미터 vs 내부 설정값)를 코드로 추적했는가(추측 금지)
- [ ] JdbcTemplate·createQuery 사용 시 SQL 문자열 조립 방식(문자열 연결 vs `?` 플레이스홀더)을 확인했는가
- [ ] ORDER BY·컬럼명 동적 삽입 지점에 허용 목록 검증이 있는지 서비스 레이어까지 추적했는가
- [ ] 각 확정 취약점에 재현 근거(파일:라인 + 입력 출처 추적)가 붙어 있는가

## Key Concepts

| 용어 | 설명 |
|---|---|
| SQL Injection | 사용자 입력이 SQL 구문의 일부로 해석되어 쿼리 로직을 공격자가 조작 |
| PreparedStatement | SQL과 데이터를 분리해 파싱. `?` 플레이스홀더 — 근본적 방어 |
| MyBatis `#{}` | PreparedStatement 파라미터 바인딩 — 안전 |
| MyBatis `${}` | 문자열 치환(SQL 조각 삽입) — 사용자 입력에 사용 시 취약 |
| JPQL Injection | JPA JPQL에서 문자열 연결로 쿼리 조립 시 발생. 파라미터 바인딩으로 방어 |
| Error-based SQLi | DB 에러 메시지로 스키마 정보 추출 |
| UNION-based SQLi | UNION SELECT로 다른 테이블 데이터 추출 |
| Time-based Blind SQLi | SLEEP() 등으로 지연을 발생시켜 조건 참/거짓 판별 |
| 허용 목록(allowlist) | ORDER BY·컬럼명 등 식별자 동적 삽입 시 유일한 안전 방어 |

## Tools & Systems

- Semgrep (룰: `rules/sqli.yml`) · grep 폴백
- MyBatis `#{}` 바인딩, JPA `setParameter`, JdbcTemplate `?` 플레이스홀더
- 참고: `references/stack-patterns.md`
