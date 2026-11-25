// How a website becomes a site for duplicate matching, without Flutter: the Public Suffix List and the shared hosts, which
// `duplicate_rules.dart` takes as functions. The app's own copy (`features/duplicates/duplicate_sites.dart` in the app) reads
// `registrableDomain` and `isSharedHost` from its AutoFill code, which holds Flutter; this one holds the same rules, and the
// app should switch to it when it takes the rest of the import code from here.
import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../../core/public_suffix_list.dart';
import 'duplicate_normalise.dart';

/// Domains under which anyone can open a site or a workspace of their own, such as `evil.okta.com` beside `acme.okta.com`: a
/// login for one is another site's. The same list as the app's AutoFill copy.
const sharedHosts = {
  'auth0.com',
  'okta.com',
  'onelogin.com',
  'slack.com',
  'wordpress.com',
  'zendesk.com',
  'atlassian.net',
  'github.io',
  'gitlab.io',
  'blogspot.com',
  'herokuapp.com',
  'netlify.app',
  'vercel.app',
  'pages.dev',
  'web.app',
  'firebaseapp.com',
  'appspot.com',
  'azurewebsites.net',
  'myshopify.com',
  'wixsite.com',
};

/// Whether [host] is one of [sharedHosts], or under one.
bool isSharedHost(String host) => sharedHosts.any((shared) => host == shared || host.endsWith('.$shared'));

// Labels of government domains, which share their suffix between services and often are public suffixes
// themselves (service.gov.uk, nsw.gov.au, state.ma.us).
const _governmentLabels = {'gov', 'gouv', 'govt', 'gob', 'gv', 'go', 'state', 'admin', 'mil'};

/// The domain an organisation owns [host] under: the Public Suffix List ([suffixes]) decides, a government host stays as it
/// is, and without the list [host] stays as it is.
String registrableDomain(String host, {PublicSuffixList? suffixes}) {
  final labels = host.split('.');
  if (suffixes == null || labels.length <= 2 || labels.skip(1).any(_governmentLabels.contains)) return host;
  return suffixes.registrableDomain(host) ?? host;
}

/// A [SiteResolver] that reads sites as `loginDomains` does: the registrable domain by
/// [suffixes] (the host as it is without the list), and an address or a shared host whole.
SiteResolver siteResolver({PublicSuffixList? suffixes}) => SiteResolver(
  registrable: (host) => registrableDomain(host, suffixes: suffixes),
  isShared: isSharedHost,
);

/// The hash of the Public Suffix List's [text], which a tag cache records: an update that changes the list changes how some
/// sites read. `none` without the list, where every host stands for itself.
String suffixListHash(String? text) => text == null ? 'none' : hash.sha256.convert(utf8.encode(text)).toString();
