// What a person typed for a website becomes the address a rule keeps (the
// add-cards-identities-and-websites plan, design decision 5), in pure Dart
// like `website_rules.dart`, which says what a pattern may hold.
import '../models/website_rule.dart';
import 'website_rules.dart';
import 'websites.dart';

/// An address made of typed text: [uri] is what the rule keeps, null when the
/// text is empty or can't be one. For a Regular expression that is refused,
/// [refusal] says why.
typedef WebsiteInput = ({String? uri, PatternRefusal? refusal});

final _addressPattern = RegExp(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([\s\S]*)$');
final _whitespace = RegExp(r'\s');
final _port = RegExp(r'^\d{1,5}$');

/// The authority of [typed], with no scheme and no user, and what follows it.
({String? scheme, String authority, String rest}) _split(String typed) {
  String? scheme;
  String authority;
  String rest;
  final match = _addressPattern.firstMatch(typed);
  if (match != null) {
    scheme = match[1]!.toLowerCase();
    authority = match[2]!;
    rest = match[3]!;
  } else {
    final end = typed.indexOf(RegExp(r'[/?#]'));
    authority = end < 0 ? typed : typed.substring(0, end);
    rest = end < 0 ? '' : typed.substring(end);
  }
  final at = authority.lastIndexOf('@');
  if (at >= 0) authority = authority.substring(at + 1);
  return (scheme: scheme, authority: authority.toLowerCase(), rest: rest);
}

/// The port [authority] names, with its colon, or an empty string.
String _portOf(String authority) {
  final colon = authority.lastIndexOf(':');
  return colon >= 0 && _port.hasMatch(authority.substring(colon + 1)) ? authority.substring(colon) : '';
}

/// [typed] with its scheme and host in lowercase and its host in ASCII form,
/// the rest as written; null when it holds no host. A user in front of the host
/// is not kept, and the host keeps its `www.`, which matters to an exact address.
String? _canonicalAddress(String typed) {
  if (_whitespace.hasMatch(typed)) return null;
  final parts = _split(typed);
  if (normaliseWebsite(parts.authority) == null) return null;
  final port = _portOf(parts.authority);
  var host = parts.authority.substring(0, parts.authority.length - port.length);
  if (host.endsWith('.')) host = host.substring(0, host.length - 1);
  final ascii = [for (final label in host.split('.')) label.runes.every((c) => c < 0x80) ? label : 'xn--${punycodeEncode(label)}']
      .join('.');
  return '${parts.scheme == null ? '' : '${parts.scheme}://'}$ascii$port${parts.rest}';
}

/// What [text], typed for a website on the rule [match] (a [WebsiteMatch]
/// number, null for Default), makes of its address:
///
/// - Default, Base domain, Never and a rule this version doesn't know: the host,
///   as [normaliseWebsite] gives it;
/// - Host: the host, with its port if one was typed;
/// - Starts with and Exact: the address, with its scheme and host in lowercase
///   and the host in ASCII form;
/// - Regular expression: the pattern as typed, unless [patternRefusal] refuses it.
///
/// Empty text, or text that isn't what the rule needs, has no [WebsiteInput.uri].
WebsiteInput websiteInput(int? match, String text) {
  if (text.trim().isEmpty) return (uri: null, refusal: null);
  switch (match) {
    case WebsiteMatch.regularExpression:
      final refusal = patternRefusal(text);
      return (uri: refusal == null ? text : null, refusal: refusal);
    case WebsiteMatch.startsWith || WebsiteMatch.exact:
      return (uri: _canonicalAddress(text.trim()), refusal: null);
    case WebsiteMatch.host:
      final host = normaliseWebsite(text);
      if (host == null) return (uri: null, refusal: null);
      return (uri: '$host${_portOf(_split(text.trim()).authority)}', refusal: null);
    default:
      return (uri: normaliseWebsite(text), refusal: null);
  }
}
