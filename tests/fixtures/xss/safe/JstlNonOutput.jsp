<%-- JSTL 비출력 컨텍스트 — EL이 반복/조건 대상일 뿐 HTML로 출력되지 않는다(오탐이면 안 됨). --%>
<c:forEach var="item" items="${board.list}">
  <c:if test="${board.visible}">visible</c:if>
</c:forEach>
