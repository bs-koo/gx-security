import java.text.SimpleDateFormat;
import java.util.Date;

// 날짜 파싱 — JWT와 무관(오탐이면 안 됨).
class DateParse {
    Date toDate(String s) throws Exception {
        return new SimpleDateFormat("yyyy-MM-dd").parse(s);
    }
}
