namespace java com.kuaizi.log4j.net.scribe

enum ResultCode {
  OK,TRY_LATER
}

struct LogEntry {
  1: string category,
  2: string message
}

service Scribe {
  ResultCode Log(1: list<LogEntry> messages);
}