# 민감정보 노출 — 스택별 실제 코드 패턴

스캐너 룰과 AI 검증이 참조하는 SQIsoft 두 스택의 구체 패턴. 실제 사업부 코드에서 관찰되는 형태 기준.

---

## spring-modern (Spring Boot + JS SPA)

### 취약 패턴

#### 1. application.yml 하드코딩 (아직 발견 안 됐으나 주의)

```yaml
# application.yml — 평문 하드코딩 예 (취약)
spring:
  datasource:
    password: ******!      # ⚠️ 실제 값 직접 기입
  mail:
    password: mailPw!9988     # ⚠️
jwt:
  secret-key: hardcoded-jwt-secret-do-not-use  # ⚠️
```

현재 sqisoft-sef-2026은 `${DB_PASSWORD}`, `${MAIL_PASSWORD}`, `${JWT_SECRET_KEY}`로 환경변수 참조 중 → **안전(오탐 제외)**

#### 2. @Value 기본값에 시크릿

```java
// ⚠️ 기본값에 실제 시크릿 — 환경변수 미설정 시 노출
@Value("${jwt.secret-key:my-super-secret-fallback-key}")
private String secretKey;
```

#### 3. 로그에 개인정보 포함

```java
// ⚠️ 로그에 비밀번호 값 자체가 출력되는 경우
log.info("로그인 시도: id={}, pw={}", userId, password);

// ⚠️ 인증 실패 메시지에 아이디 포함 — 사용자 열거 가능 (Medium)
log.debug("인증 실패: 사용자 {} 의 비밀번호가 일치하지 않음", lgnId);
// → AuthServiceImpl.java:73 에서 실제 발견됨
```

#### 4. 응답 DTO 과다 노출

```java
// ⚠️ @JsonIgnore 없이 비밀번호 해시가 응답에 포함
public class UserDto {
    private String userId;
    private String password;      // ⚠️ 직렬화 제외 필요
    private String encryptedPwd;  // ⚠️
}
```

### 안전 패턴 (오탐 주의)

```yaml
# application.yml — 환경변수 참조 (안전)
spring:
  datasource:
    password: ${DB_PASSWORD}      # 정상 — placeholder
  mail:
    password: ${MAIL_PASSWORD}    # 정상
jwt:
  secret-key: ${JWT_SECRET_KEY}   # 정상
```

```java
// @JsonIgnore 적용 (안전)
public class UserDto {
    private String userId;
    @JsonIgnore
    private String password;
}

// 로그에 값 대신 마스킹된 식별자만 사용 (안전)
log.info("비밀번호 초기화 성공: userId={}", userId);  // userId만, 값은 없음
```

---

## jsp-legacy (JSP/Servlet + Maven WAR — Gseed_Web_Renew 기준)

### 취약 패턴

#### 1. globals.properties 하드코딩 — 실제 발견됨 ★★★

```properties
# egovProps/globals.properties — 실제 확인된 취약점
Globals.Password=Db@ssw0rd!                          # ⚠️ DB 비밀번호 평문 (Critical)
Globals.Url=jdbc:postgresql://10.0.0.5:5432/appdb  # ⚠️ 내부 DB IP 노출
Globals.gbcsApiKey=0123456789abcdef0123456789abcdef  # ⚠️ 외부 API 키 평문 (High)
Member.InitPassword=InitP@ss2020!                      # ⚠️ 관리자 초기 비밀번호 (High)
Globals.recaptcha.secretKey=6LcEXAMPLE_dummy_recaptcha_secret_key_xx  # ⚠️ reCAPTCHA 비밀키
# prod/globals.properties: DB URL이 RDS 엔드포인트로 변경됨 — 동일 비밀번호 사용
Globals.Url=jdbc:postgresql://your-db.xxxxxx.ap-northeast-2.rds.amazonaws.com:5432/gseed
```

#### 2. context-datasource.xml 연동

```xml
<!-- context-datasource.xml — globals.properties 값을 그대로 사용 -->
<property name="password" value="${Globals.Password}"/>
<!-- Globals.Password 자체가 평문이므로 최종적으로 평문 비밀번호가 사용됨 -->
```

#### 3. CertiController 하드코딩 API 키 — 실제 발견됨 ★★

```java
// CertiController.java:1441 — 주소검색 API 인증키 소스 하드코딩
String confmKey = "QVBJX0tFWV9QTEFDRUhPTERFUg==";
// ※ Base64 디코딩하면 실제 API 인증키 값이 나옴
```

#### 4. JSP 주석 내 계정정보 패턴

```jsp
<%-- 주석 안에 테스트 계정 정보 (실제 취약) --%>
<%-- DB: gseed / Db@ssw0rd! --%>
<%-- 테스트 계정: admin / ****** --%>
```

#### 5. System.out.println 개인정보

```java
// 레거시 코드에서 흔한 패턴 (취약)
System.out.println("사용자 로그인: " + userId + ", " + password);
```

### 안전 패턴 (오탐 주의)

```properties
# 안전: 환경변수/외부 주입 참조
Globals.Password=${DB_PASSWORD}

# 안전: reCAPTCHA siteKey는 공개값 (HTML에 노출 정상)
Globals.recaptcha.siteKey=6LcEXAMPLE_dummy_recaptcha_site_key_yyyy
```

```java
// 안전: 마스킹 로깅
log.info("비밀번호 초기화 완료: userId={}", userId);  // 값(비밀번호)은 로그에 없음
```

---

## 공통 보조 점검 (스캐너가 못 잡음 → AI가 보강)

| 점검 항목 | 위치 | 판정 기준 |
|---|---|---|
| Base64 인코딩 자격증명 | Java 소스 (`confmKey = "U01TX..."`) | 디코딩 후 API 키 형태이면 High |
| 주석 내 계정 정보 | JSP·Java 주석 | 발견 즉시 High |
| 예외 스택트레이스 노출 | `web.xml <error-page>` 미설정, Spring `server.error.include-stacktrace` | 미설정 시 Medium |
| DTO 응답 과다 노출 | `@JsonIgnore` 미적용 비밀번호 필드 | High |
| 개인정보 평문 저장 | DB 컬럼 타입·암호화 여부 | 주민번호·비밀번호 SHA1·MD5 해시 → High (단방향 강도 확인) |

---

## 오탐(False Positive) 가이드

스캐너가 `password`·`secret` 키워드를 잡아도 아래는 취약이 아니다.

1. **환경변수 참조** — `${DB_PASSWORD}`, `${JWT_SECRET_KEY}` → 오탐
2. **reCAPTCHA siteKey** — 공개값, HTML 노출 정상 → 오탐 (secretKey는 취약)
3. **테스트 픽스처·단위테스트** — `@SpringBootTest` 내 더미 값(`test-secret-123`) → 낮은 위험, 별도 기록
4. **비밀번호 필드명만 있고 값 없음** — `password:` (값 없음) → 오탐
5. **검증 로직 내 비밀번호 문자열 비교** — `if ("OLD_PW".equals(input))` 형태가 도메인 로직이면 컨텍스트 확인 후 판정
