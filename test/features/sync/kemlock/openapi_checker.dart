// A small OpenAPI checker for the contract test (add-kemlock-server-sync, design decision 15 and task 13.2): it holds
// what the client sends, and what the fake servers answer, to the server's OpenAPI 3.1 document in
// test/fixtures/server/openapi.json (copied by tool/server/copy_vectors.sh, never edited).
//
// For each exchange it finds the path template and the method of the request, then checks
//
// - the path parameters, the query parameters (each one the spec lists, the required ones present, the types), and the
//   headers (the required ones present, the types, and no header of its own that the spec lacks);
// - the `Authorization: DPoP` and `DPoP` headers of a route with the `dpop` security scheme;
// - the JSON body against the request body's schema, and the content type against the ones the spec lists;
// - the status of the answer against the spec's responses (a 401, 429 or 5xx the spec leaves out of a route is let
//   through, as it can come on any route, but its body must still be a problem), a 204 or 304 with no body, the content
//   type and the JSON body against the response's schema.
//
// The schema subset is what the spec uses: `$ref` to `#/components/schemas`, `type` (a name or a list, which is how this
// spec says nullable), `properties`, `required`, `additionalProperties` (`false`, or a schema), `items`, `enum`,
// `allOf`, `oneOf`, `anyOf`, `minimum`, and the formats `uuid`, `int32` and `int64`. A property the schema doesn't list
// is a violation in a request and in an answer, whether or not the schema says `additionalProperties: false`; a free
// object (`{}`) lists nothing and takes anything. `description`, `default` and the rest are skipped, as is the body of an
// octet stream and a WebSocket upgrade.
//
// A violation is recorded, never thrown, so the fake that answers keeps answering; the test reads [violations].
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../../../crypto/account/server_vectors.dart';

/// A JSON object.
typedef Json = Map<String, Object?>;

/// One thing the client sent, or a fake answered, that the spec doesn't allow.
class ContractViolation {
  const ContractViolation(this.operation, this.where, this.message);

  /// `METHOD /kem/v1/template` of the route, or `METHOD /path` when the spec has none.
  final String operation;

  /// Where in the exchange: `request body $.writes[0]`, `answer 200 body $.items`, `query since`, `header If-Match`, ...
  final String where;

  final String message;

  @override
  String toString() => '$operation: $where: $message';
}

/// A violation known to be the spec's fault, not the client's: the server session is told, and the contract test lets
/// it pass until the spec says otherwise. It matches the [operation] exactly, and [at] must be in the violation's where or message.
class ContractGap {
  const ContractGap(this.operation, this.at, this.reason);

  final String operation;
  final String at;

  /// What the server's code does that the spec doesn't say, for the server session.
  final String reason;

  bool covers(ContractViolation violation) => violation.operation == operation && '${violation.where} ${violation.message}'.contains(at);
}

/// The server's OpenAPI document, as JSON, with the lookups the checker needs.
class OpenApiSpec {
  OpenApiSpec(this.json) {
    final paths = json['paths'];
    if (paths is! Json) throw const FormatException('an OpenAPI document has paths');
    for (final template in paths.keys) {
      _templates.add((template: template, segments: template.split('/')));
    }
  }

  /// The copied document, test/fixtures/server/openapi.json, as a new tree each time, so a test may change it.
  factory OpenApiSpec.fixture() => OpenApiSpec(copyOf(readServerVector('openapi.json')! as Json));

  /// A deep copy of [json].
  static Json copyOf(Json json) => jsonDecode(jsonEncode(json)) as Json;

  final Json json;
  final _templates = <({String template, List<String> segments})>[];

  /// The operations of the document as `METHOD template`.
  Set<String> get operations => {
    for (final MapEntry(:key, :value) in (json['paths']! as Json).entries)
      for (final method in (value! as Json).keys)
        if (methods.contains(method)) '${method.toUpperCase()} $key',
  };

  /// The keys of a path item that are methods.
  static const methods = {'get', 'put', 'post', 'delete', 'patch', 'options', 'head', 'trace'};

  /// What a local `$ref` points at.
  Object? pointer(String ref) {
    if (!ref.startsWith('#/')) throw ArgumentError.value(ref, 'ref', 'only local references');
    Object? node = json;
    for (final part in ref.substring(2).split('/')) {
      if (node is! Json) throw StateError('the reference $ref has nothing at $part');
      node = node[part.replaceAll('~1', '/').replaceAll('~0', '~')];
    }
    if (node == null) throw StateError('the reference $ref points at nothing');
    return node;
  }

  /// [node], or what it refers to, followed through to a node that isn't a reference.
  Object? resolve(Object? node) {
    var current = node;
    for (var hops = 0; current is Json && current[r'$ref'] is String; hops++) {
      if (hops > 32) throw StateError('a loop of references');
      current = pointer(current[r'$ref']! as String);
    }
    return current;
  }

  /// The path template that [path] fits, with its parameters; of those that fit, the one with the most fixed segments,
  /// and among equals the one that has [method]. Null when none fits.
  ({String template, Json item, Map<String, String> params})? find(String path, String method) {
    final parts = path.split('/');
    ({String template, Map<String, String> params, int fixed})? best;
    var bestHasMethod = false;
    for (final candidate in _templates) {
      if (candidate.segments.length != parts.length) {
        continue;
      }
      final params = <String, String>{};
      var fixed = 0;
      var fits = true;
      for (var i = 0; i < parts.length && fits; i++) {
        final segment = candidate.segments[i];
        if (segment.startsWith('{') && segment.endsWith('}')) {
          if (parts[i].isEmpty) {
            fits = false;
          } else {
            params[segment.substring(1, segment.length - 1)] = Uri.decodeComponent(parts[i]);
          }
        } else if (segment == parts[i]) {
          fixed++;
        } else {
          fits = false;
        }
      }
      if (!fits) {
        continue;
      }
      final item = (json['paths']! as Json)[candidate.template]! as Json;
      final has = item.containsKey(method.toLowerCase());
      if (best == null || fixed > best.fixed || (fixed == best.fixed && has && !bestHasMethod)) {
        best = (template: candidate.template, params: params, fixed: fixed);
        bestHasMethod = has;
      }
    }
    if (best == null) {
      return null;
    }
    return (template: best.template, item: (json['paths']! as Json)[best.template]! as Json, params: best.params);
  }
}

/// Checks exchanges against an [OpenApiSpec] and keeps what it found.
class OpenApiChecker {
  OpenApiChecker(this.spec);

  /// The checker the fake servers report to while a contract test runs, or null.
  static OpenApiChecker? active;

  final OpenApiSpec spec;

  /// Everything found, in order.
  final violations = <ContractViolation>[];

  /// The operations exchanged, `METHOD template`, and each with the statuses answered, `METHOD template status`.
  final operations = <String>{};
  final answers = <String>{};

  /// How many exchanges were checked, and how many were of a path outside `/kem/v1`, which are not.
  var checked = 0;
  var skipped = 0;

  /// Whether a route with the `dpop` scheme needs a `DPoP` header, the proof. A test that builds the client with no
  /// proof (the sync kit's) turns it off; the proof itself is `KmApi`'s one place and has its own tests.
  var requireProof = true;

  static const _apiPrefix = '/kem/v1/';

  /// Headers that belong to HTTP itself, or to the client library, and need no mention in the spec.
  static const _standardHeaders = {
    'accept',
    'accept-encoding',
    'accept-language',
    'authorization',
    'cache-control',
    'connection',
    'content-length',
    'content-type',
    'dpop',
    'host',
    'pragma',
    'user-agent',
  };

  /// The violations that [gaps] don't cover.
  List<ContractViolation> unexpected(List<ContractGap> gaps) => [
    for (final violation in violations)
      if (!gaps.any((gap) => gap.covers(violation))) violation,
  ];

  /// Checks [request] and the [response] it was answered with.
  void exchange(http.Request request, http.Response response) {
    final route = _route(request);
    if (route == null) {
      return;
    }
    _request(route, request);
    _answer(route, response);
  }

  /// Checks [request] alone, for a test that answers it by hand.
  void requestOnly(http.Request request) {
    final route = _route(request);
    if (route != null) {
      _request(route, request);
    }
  }

  void _add(String operation, String where, String message) => violations.add(ContractViolation(operation, where, message));

  _Route? _route(http.Request request) {
    final path = request.url.path;
    final method = request.method.toUpperCase();
    if (!path.startsWith(_apiPrefix)) {
      skipped++;
      return null;
    }
    checked++;
    final found = spec.find(path, method);
    if (found == null) {
      _add('$method $path', 'route', 'the spec has no such path');
      return null;
    }
    final operation = '$method ${found.template}';
    final op = found.item[method.toLowerCase()];
    if (op is! Json) {
      final has = found.item.keys.where(OpenApiSpec.methods.contains).join(', ');
      _add(operation, 'method', 'the spec has no $method on this path (it has $has)');
      return null;
    }
    operations.add(operation);
    return _Route(operation, method, found.template, op, found.item, found.params);
  }

  List<Json> _parameters(Json item, Json op) => [
    for (final list in [item['parameters'], op['parameters']])
      if (list is List<Object?>)
        for (final raw in list)
          if (spec.resolve(raw) case final Json parameter) parameter,
  ];

  void _request(_Route route, http.Request request) {
    final operation = route.operation;
    final op = route.op;
    final parameters = _parameters(route.item, op);

    for (final parameter in parameters.where((p) => p['in'] == 'path')) {
      final name = parameter['name']! as String;
      final value = route.params[name];
      if (value != null) {
        _text(operation, 'path parameter $name', parameter['schema'], value);
      }
    }

    final queries = {for (final p in parameters.where((p) => p['in'] == 'query')) p['name']! as String: p};
    for (final MapEntry(:key, :value) in request.url.queryParametersAll.entries) {
      final declared = queries[key];
      if (declared == null) {
        _add(operation, 'query $key', 'the spec lists no query parameter $key');
        continue;
      }
      // An exploded form array (`?vault=a&vault=b`) repeats the name, one item per value
      final schema = spec.resolve(declared['schema']);
      final exploded = schema is Json && schema['type'] == 'array' && declared['explode'] != false;
      for (final text in value) {
        _text(operation, 'query $key', exploded ? schema['items'] : declared['schema'], text);
      }
    }
    for (final MapEntry(:key, :value) in queries.entries) {
      if (value['required'] == true && !request.url.queryParametersAll.containsKey(key)) {
        _add(operation, 'query $key', 'the spec requires it and the request has none');
      }
    }

    final headers = {for (final MapEntry(:key, :value) in request.headers.entries) key.toLowerCase(): value};
    final declaredHeaders = {for (final p in parameters.where((p) => p['in'] == 'header')) (p['name']! as String).toLowerCase(): p};
    for (final MapEntry(:key, :value) in declaredHeaders.entries) {
      final sent = headers[key] ?? (key == 'content-length' ? '${request.contentLength}' : null);
      if (sent == null) {
        if (value['required'] == true) {
          _add(operation, 'header ${value['name']}', 'the spec requires it and the request has none');
        }
        continue;
      }
      _text(operation, 'header ${value['name']}', value['schema'], sent);
    }
    for (final name in headers.keys) {
      if (!_standardHeaders.contains(name) && !declaredHeaders.containsKey(name)) {
        _add(operation, 'header $name', 'the spec lists no header $name');
      }
    }
    final secured = op['security'] is List<Object?> && (op['security']! as List<Object?>).isNotEmpty;
    final authorization = headers['authorization'];
    if (secured) {
      if (authorization == null || !authorization.startsWith('DPoP ') || authorization.length <= 5) {
        _add(operation, 'header Authorization', 'the route takes Authorization: DPoP <token>');
      }
      if (requireProof && !headers.containsKey('dpop')) {
        _add(operation, 'header DPoP', 'the route takes a DPoP proof');
      }
    } else if (authorization != null) {
      _add(operation, 'header Authorization', 'the route takes no token');
    }

    _requestBody(operation, op, request, headers['content-type']);
  }

  void _requestBody(String operation, Json op, http.Request request, String? contentType) {
    final body = request.bodyBytes;
    final declared = spec.resolve(op['requestBody']);
    if (declared is! Json) {
      if (body.isNotEmpty) {
        _add(operation, 'request body', 'the spec has no request body');
      }
      return;
    }
    if (body.isEmpty) {
      if (declared['required'] == true) {
        _add(operation, 'request body', 'the spec requires a body and the request has none');
      }
      return;
    }
    final content = declared['content'];
    final media = _mediaType(contentType);
    final listed = content is Json ? content[media] : null;
    if (listed is! Json) {
      final lists = content is Json ? content.keys.join(', ') : 'none';
      _add(operation, 'request content type', 'the spec lists $lists; the request is $media');
      return;
    }
    if (media == 'application/json') {
      final Object? value;
      try {
        value = jsonDecode(utf8.decode(body));
      } on FormatException {
        _add(operation, 'request body', 'is not JSON');
        return;
      }
      for (final error in _Schemas(spec).check(listed['schema'], value)) {
        _add(operation, 'request body', error);
      }
    }
  }

  void _answer(_Route route, http.Response response) {
    final operation = route.operation;
    final status = response.statusCode;
    answers.add('${route.method} ${route.template} $status');
    final responses = route.op['responses'];
    final declared = responses is Json ? spec.resolve(responses['$status'] ?? responses['default']) : null;
    final where = 'answer $status';
    final media = _mediaType(response.headers['content-type']);
    if (declared is! Json) {
      // A 401 (the nonce, a session that ended), a 429 or a 5xx can come from any route, and the spec doesn't list them on all
      final everywhere = status == 401 || status == 429 || status >= 500;
      if (!everywhere) {
        _add(operation, where, 'the spec lists ${responses is Json ? responses.keys.join(', ') : 'no answers'}');
        return;
      }
      if (response.bodyBytes.isNotEmpty) {
        _problem(operation, where, media, response);
      }
      return;
    }
    if (status == 204 || status == 304 || status == 101) {
      if (response.bodyBytes.isNotEmpty) {
        _add(operation, where, 'has a body, and a $status has none');
      }
      return;
    }
    final content = declared['content'];
    if (content is! Json) {
      return;
    }
    final listed = content[media];
    if (listed is! Json) {
      _add(operation, '$where content type', 'the spec lists ${content.keys.join(', ')}; the answer is ${media.isEmpty ? 'none' : media}');
      return;
    }
    if (media == 'application/problem+json') {
      _problem(operation, where, media, response);
    } else if (media == 'application/json') {
      final Object? value;
      try {
        value = jsonDecode(utf8.decode(response.bodyBytes));
      } on FormatException {
        _add(operation, '$where body', 'is not JSON');
        return;
      }
      for (final error in _Schemas(spec).check(listed['schema'], value)) {
        _add(operation, '$where body', error);
      }
    }
  }

  /// A problem body: RFC 9457's `type`, `title` and `status`, and whatever else the problem carries (`itemId`,
  /// `currentRevision`, `reason`, ...), which the spec's `ProblemDoc` doesn't list.
  void _problem(String operation, String where, String media, http.Response response) {
    if (media != 'application/problem+json') {
      _add(operation, '$where content type', 'a problem is application/problem+json, not ${media.isEmpty ? 'none' : media}');
    }
    final Object? value;
    try {
      value = jsonDecode(utf8.decode(response.bodyBytes));
    } on FormatException {
      _add(operation, '$where body', 'is not JSON');
      return;
    }
    for (final error in _Schemas(spec).check(const {r'$ref': '#/components/schemas/ProblemDoc'}, value, extras: true)) {
      _add(operation, '$where body', error);
    }
  }

  /// A path, query or header value, which is text, as the schema's type reads it.
  void _text(String operation, String where, Object? schema, String text) {
    final resolved = spec.resolve(schema);
    final names = resolved is Json ? resolved['type'] : null;
    final types = names is List<Object?> ? names : [names];
    Object? value = text;
    if (types.contains('integer') && !types.contains('string')) {
      value = int.tryParse(text) ?? text;
    } else if (types.contains('boolean') && !types.contains('string')) {
      value = text == 'true' ? true : (text == 'false' ? false : text);
    }
    for (final error in _Schemas(spec).check(schema, value)) {
      _add(operation, where, error);
    }
  }

  static String _mediaType(String? contentType) => (contentType ?? '').split(';').first.trim().toLowerCase();
}

/// The route an exchange is for.
class _Route {
  const _Route(this.operation, this.method, this.template, this.op, this.item, this.params);

  final String operation;
  final String method;
  final String template;
  final Json op;
  final Json item;
  final Map<String, String> params;
}

/// The schema check.
class _Schemas {
  _Schemas(this.spec);

  final OpenApiSpec spec;

  static final _uuid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');

  /// What is wrong with [value] against [schema], as text; nothing for a value that fits. With [extras], a property the
  /// schema doesn't list is let through at the top level and below.
  List<String> check(Object? schema, Object? value, {bool extras = false}) {
    final errors = <String>[];
    _visit(schema, value, r'$', errors, extras: extras, unknown: true);
    return errors;
  }

  void _visit(Object? raw, Object? value, String path, List<String> errors, {required bool extras, required bool unknown}) {
    final schema = spec.resolve(raw);
    if (schema is! Json) {
      return;
    }
    final parts = schema['allOf'];
    if (parts is List<Object?>) {
      for (final part in parts) {
        _visit(part, value, path, errors, extras: extras, unknown: false);
      }
    }
    for (final key in const ['oneOf', 'anyOf']) {
      final alternatives = schema[key];
      if (alternatives is List<Object?>) {
        var matching = 0;
        for (final alternative in alternatives) {
          final inner = <String>[];
          _visit(alternative, value, path, inner, extras: extras, unknown: true);
          if (inner.isEmpty) {
            matching++;
          }
        }
        if (key == 'oneOf' ? matching != 1 : matching == 0) {
          errors.add('$path fits $matching of the ${alternatives.length} alternatives of $key (it is ${_describe(value)})');
        }
      }
    }
    final type = schema['type'];
    if (type != null) {
      final names = type is List<Object?> ? type.cast<String>() : <String>[type as String];
      if (!names.any((name) => _is(name, value))) {
        errors.add('$path is ${_describe(value)}, and the spec says ${names.join(' or ')}');
        return;
      }
    }
    final allowed = schema['enum'];
    if (allowed is List<Object?> && !allowed.contains(value)) {
      errors.add('$path is not one of ${allowed.join(', ')}');
    }
    if (value is String && schema['format'] == 'uuid' && !_uuid.hasMatch(value)) {
      errors.add('$path is not a UUID');
    }
    if (value is num) {
      final minimum = schema['minimum'];
      if (minimum is num && value < minimum) {
        errors.add('$path is below the minimum $minimum');
      }
      if (schema['format'] == 'int32' && (value < -2147483648 || value > 2147483647)) {
        errors.add('$path is outside int32');
      }
    }
    if (value is Json) {
      _object(schema, value, path, errors, extras: extras, unknown: unknown);
    } else if (value is List<Object?>) {
      final items = schema['items'];
      if (items != null) {
        for (var i = 0; i < value.length; i++) {
          _visit(items, value[i], '$path[$i]', errors, extras: extras, unknown: true);
        }
      }
    }
  }

  Json _properties(Json schema) {
    final out = <String, Object?>{};
    final own = schema['properties'];
    if (own is Json) {
      out.addAll(own);
    }
    final parts = schema['allOf'];
    if (parts is List<Object?>) {
      for (final part in parts) {
        final resolved = spec.resolve(part);
        if (resolved is Json) {
          out.addAll(_properties(resolved));
        }
      }
    }
    return out;
  }

  void _object(Json schema, Json value, String path, List<String> errors, {required bool extras, required bool unknown}) {
    final properties = _properties(schema);
    final required = schema['required'];
    if (required is List<Object?>) {
      for (final name in required) {
        if (!value.containsKey(name)) {
          errors.add('$path.$name is missing');
        }
      }
    }
    final more = schema['additionalProperties'];
    for (final MapEntry(:key, value: member) in value.entries) {
      final declared = properties[key];
      if (declared != null) {
        _visit(declared, member, '$path.$key', errors, extras: extras, unknown: true);
      } else if (more is Json) {
        _visit(more, member, '$path.$key', errors, extras: extras, unknown: true);
      } else if (unknown && !extras && (more == false || properties.isNotEmpty)) {
        errors.add('$path.$key is not in the spec');
      }
    }
  }

  static bool _is(String name, Object? value) => switch (name) {
    'string' => value is String,
    'integer' => value is int || (value is double && value.isFinite && value == value.truncateToDouble()),
    'number' => value is num,
    'boolean' => value is bool,
    'null' => value == null,
    'array' => value is List<Object?>,
    'object' => value is Json,
    _ => true,
  };

  static String _describe(Object? value) => switch (value) {
    null => 'null',
    bool() => 'a boolean',
    int() => 'an integer',
    num() => 'a number',
    String() => 'a string',
    List<Object?>() => 'an array',
    Map<Object?, Object?>() => 'an object',
    _ => 'something else',
  };
}
