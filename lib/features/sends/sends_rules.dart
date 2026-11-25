/// The rules of the Sends screens that need no UI: how long to wait after too many tries, and which refusals mean a
/// Send is closed or a link opens nothing. The app's `sends_support.dart` keeps the words and formats that need Flutter;
/// the browser extension reads these.
///
/// Pure Dart, no Flutter.
library;

import '../sync/kemlock/km_sends_api.dart';
import 'sends_recipient.dart';

/// The wait a rate-limited answer asks for, in whole seconds, at least 1 and at most a minute: the server's limit is
/// per minute, and an answer with no wait is taken as one.
int sendsWaitSeconds(int? retryAfter) => (retryAfter ?? 60).clamp(1, 60);

/// Whether [error] is a Send the link can't open for being closed.
bool isNotAvailable(Object error) => error is SendsError && error.problem == SendsProblem.notFound;

/// Whether [error] is a link that opens nothing: a payload that isn't the Send's own.
bool isDoesntOpen(Object error) => error is SendsDoesntOpen;
