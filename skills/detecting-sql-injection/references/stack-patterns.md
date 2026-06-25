# SQL Injection — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## jsp-legacy (JSP/Servlet + eGovFramework + MyBatis XML + Maven WAR)

### 취약 패턴

#### 1. JSP Scriptlet — Statement 문자열 연결 (Critical)

```java
// JSP scriptlet 또는 Servlet에서 사용자 입력을 SQL 문자열에 직접 연결
String keyword = request.getParameter("keyword");
String sql = "SELECT * FROM board WHERE title LIKE '%" + keyword + "%'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);   // ⚠️ Critical SQLi
```

공격 페이로드: `keyword = ' OR '1'='1` → 전체 데이터 노출
공격 페이로드: `keyword = '; DROP TABLE board;--` → 테이블 삭제 (DB 권한에 따라)

#### 2. MyBatis Mapper XML — `${}` 문자열 치환 (Critical)

```xml
<!-- egovframework/sqlmap/ 하위 Mapper XML — ${}는 SQL 조각 치환, 위험 -->
<select id="searchBoards" parameterType="BoardVo" resultType="BoardVo">
    SELECT * FROM board
    WHERE 1=1
    <if test="keyword != null and keyword != ''">
        AND title LIKE '%${keyword}%'    <!-- ⚠️ ${}로 직접 삽입 -->
    </if>
    ORDER BY ${sortColumn} ${sortOrder}  <!-- ⚠️ 정렬 컬럼/방향도 취약 -->
</select>
```

`Gseed_Web_Renew` 에서는 iBATIS/MyBatis XML이
`src/main/resources/egovframework/sqlmap/` 하위에 위치.

#### 3. MyBatis — 로그인 쿼리 `${}` (Critical)

```xml
<!-- 로그인 — ${}로 사용자명·비밀번호 삽입 시 인증 우회 가능 -->
<select id="selectUser" parameterType="UserVo" resultType="UserVo">
    SELECT * FROM users
    WHERE user_id = '${userId}'
    AND   password = '${password}'   <!-- ⚠️ 인증 우회 -->
</select>
```

공격: `userId = ' OR '1'='1'--` → 비밀번호 검증 우회

---

### 안전 패턴 (이건 취약 아님 — 오탐 주의)

> **추적 원칙**: `${}`가 보여도 입력 출처를 역추적한다. 서비스 레이어 allowlist(ORDER BY 컬럼 등)나
> 쿼리 빌더 래퍼를 거치면 안전일 수 있다. 한 줄 스니펫이 아니라 호출 체인(Controller→Service→Mapper)을
> 따라가 확정한다.

```xml
<!-- MyBatis #{} — PreparedStatement 바인딩, 완전히 안전 -->
<select id="searchBoards" parameterType="BoardVo" resultType="BoardVo">
    SELECT * FROM board
    WHERE 1=1
    <if test="keyword != null and keyword != ''">
        AND title LIKE CONCAT('%', #{keyword}, '%')   <!-- 안전 -->
    </if>
</select>

<select id="selectUser" parameterType="UserVo" resultType="UserVo">
    SELECT * FROM users
    WHERE user_id = #{userId}
    AND   password = #{password}   <!-- 안전 -->
</select>
```

```java
// PreparedStatement — 안전
String sql = "SELECT * FROM board WHERE title LIKE ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, "%" + keyword + "%");
ResultSet rs = ps.executeQuery();   // 안전
```

---

## spring-modern (Spring Boot + MyBatis + JPA + JdbcTemplate)

### 취약 패턴

#### 1. JPA EntityManager — JPQL 문자열 연결 (High)

```java
// JPQL도 문자열 연결 시 Injection 가능
@Repository
public class BoardRepository {
    @PersistenceContext
    private EntityManager em;

    public List<Board> search(String keyword) {
        String jpql = "SELECT b FROM Board b WHERE b.title LIKE '%" + keyword + "%'";
        return em.createQuery(jpql, Board.class).getResultList();  // ⚠️ JPQL Injection
    }
}
```

#### 2. JdbcTemplate — 문자열 연결 (High)

```java
// JdbcTemplate에서도 SQL 문자열 직접 연결 시 취약
@Repository
public class UserRepository {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<User> findByName(String name) {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        return jdbcTemplate.query(sql, new UserRowMapper());  // ⚠️ SQLi
    }
}
```

#### 3. MyBatis Mapper XML — `${}` (spring-modern도 MyBatis 혼용) (High)

```xml
<!-- sqisoft-sef-2026 MyBatis: mybatis/mapper/ 하위 -->
<!-- ${} 는 spring-modern 에서도 동일하게 위험 -->
<select id="searchUsers" parameterType="map" resultType="UserVo">
    SELECT * FROM users
    WHERE 1=1
    <if test="searchType != null">
        AND ${searchType} LIKE #{keyword}   <!-- ⚠️ 컬럼명 동적 삽입 -->
    </if>
    ORDER BY ${sortCol}                     <!-- ⚠️ 정렬 컬럼 동적 삽입 -->
</select>
```

#### 4. @Query — native query 동적 조립 (Medium)

```java
// Spring Data JPA @Query에서 nativeQuery=true + 문자열 연결
// 애노테이션 값 자체는 컴파일 타임 상수이나,
// 아래처럼 동적 조립 후 EntityManager로 실행 시 위험
public List<Board> searchNative(String table, String keyword) {
    String sql = "SELECT * FROM " + table + " WHERE title = ?1";  // ⚠️ 테이블명 삽입
    return em.createNativeQuery(sql, Board.class)
             .setParameter(1, keyword)
             .getResultList();
}
```

#### 5. 정렬·페이징 컬럼명 동적 삽입 — 허용 목록 없음 (Medium)

```xml
<!-- sqisoft-sef-2026 BoardMapper.xml 유형 — 실제 패턴 -->
<select id="selectBoardList" parameterType="PageRequest" resultType="BoardVo">
    SELECT *
    FROM board
    ORDER BY ${sortColumn} ${sortDirection}   <!-- ⚠️ allowlist 없으면 취약 -->
    LIMIT #{pageSize} OFFSET #{offset}
</select>
```

---

### 안전 패턴 (이건 취약 아님 — 오탐 주의)

```java
// JPA 파라미터 바인딩 — 안전
public List<Board> search(String keyword) {
    return em.createQuery(
        "SELECT b FROM Board b WHERE b.title LIKE :keyword", Board.class)
        .setParameter("keyword", "%" + keyword + "%")
        .getResultList();  // 안전
}

// Spring Data JPA 메서드 쿼리 — 안전
List<Board> findByTitleContaining(String keyword);

// JdbcTemplate ? 플레이스홀더 — 안전
String sql = "SELECT * FROM users WHERE name = ?";
jdbcTemplate.query(sql, new UserRowMapper(), name);  // 안전
```

```xml
<!-- MyBatis #{} — 안전 -->
<select id="selectBoardList" resultType="BoardVo">
    SELECT * FROM board
    WHERE title LIKE CONCAT('%', #{keyword}, '%')
    LIMIT #{pageSize} OFFSET #{offset}
</select>
```

```java
// ORDER BY 허용 목록 검증 — 안전
private static final Set<String> ALLOWED_SORT = Set.of("title", "created_at", "view_count");

public List<BoardVo> list(String sortCol) {
    if (!ALLOWED_SORT.contains(sortCol)) sortCol = "created_at";
    return boardMapper.selectBoardList(sortCol);
}
```

---

## 공통 — 위험 가중 요소 (스캐너가 못 잡음 → AI가 보강)

| 점검 | 위치 | 판정 |
|---|---|---|
| DB 예외 메시지 응답 노출 | GlobalExceptionHandler, JSP error page | Error-based SQLi 피해 확대 — 에러 정보 숨기기 필요 |
| DB 계정 과도한 권한 | datasource 설정, DBA 계정 사용 | SQLi 성공 시 피해 폭 증가 — 최소 권한 원칙 |
| Second-order SQLi | 저장 후 다른 쿼리에서 재사용 | 저장 시 안전해도 출력에서 SQL 재조합 시 위험 |
| 저장 프로시저 동적 인수 | CALL proc(${param}) | 프로시저 내부도 동일하게 점검 |

---

## 오탐(False Positive) 가이드

스캐너가 `${}` 또는 문자열 연결을 잡아도 아래는 취약이 아니다.

1. **MyBatis `#{}`** — PreparedStatement 바인딩. 완전 안전. `${}` 와 혼동 금지.
2. **`${}` 가 내부 설정값만 사용** — `application.yml`의 스키마명·테이블 접두사 등 사용자 입력이 아닌 경우. 단 설정값 자체의 무결성 확인 필요.
3. **JdbcTemplate `?` 플레이스홀더** — 문자열 연결이 아닌 `?` + 인수 배열 전달 형태는 안전.
4. **Spring Data JPA 메서드 쿼리(`findBy...`)** — 컴파일 타임에 바인딩 구조 결정. 안전.
5. **하드코딩 상수만 조합** — 사용자 입력이 전혀 없는 상수 문자열 연결. 안전.
6. **`ORDER BY` 허용 목록 검증 후 `${}`** — 서비스 레이어에서 허용 목록 검증이 확인된 경우 조건부 허용. 단 검증 코드를 직접 확인해야 함.

오탐으로 판정하면 리포트의 "오탐 제외"에 사유 한 줄로 남긴다.
