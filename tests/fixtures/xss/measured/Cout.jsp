<%-- FR-4 measured (xss): <c:out> 래핑은 안전형. semgrep pattern-not-regex(escapeXml|<c:out)
     실효성 실측용. 폴백은 후처리로, semgrep은 pattern-not-regex 로 제외 → 관측값 CI 확정. --%>
<c:out value="${board.title}"/>
