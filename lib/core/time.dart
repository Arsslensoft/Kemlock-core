/// [time] as JavaScript's `Date.toISOString()` writes it: UTC, to the millisecond.
String isoString(DateTime time) {
  final utc = time.toUtc();
  String two(int n) => n.toString().padLeft(2, '0');
  return '${utc.year.toString().padLeft(4, '0')}-${two(utc.month)}-${two(utc.day)}'
      'T${two(utc.hour)}:${two(utc.minute)}:${two(utc.second)}.${utc.millisecond.toString().padLeft(3, '0')}Z';
}
