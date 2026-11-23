import 'json.dart';

/// How long a generated password no save followed is kept.
const generatedPasswordDays = 30;

/// A password AutoFill generated and filled, which no saved login holds
/// (openspec: password-autofill): kept in the vault for
/// [generatedPasswordDays] days, listed under the generator's "Recently
/// generated". Never synced or exported.
class GeneratedPassword {
  const GeneratedPassword({required this.password, this.site, required this.at});

  factory GeneratedPassword.fromJson(Map<String, Object?> json) =>
      GeneratedPassword(password: asString(json['password']), site: asOptionalString(json['site']), at: asInt(json['at']) ?? 0);

  final String password;

  /// The host it was generated for, when it was a website.
  final String? site;

  /// Epoch ms it was generated.
  final int at;

  Map<String, Object?> toJson() => {'password': password, 'site': ?site, 'at': at};

  @override
  bool operator ==(Object other) => other is GeneratedPassword && other.password == password && other.site == site && other.at == at;

  @override
  int get hashCode => Object.hash(password, site, at);

  /// Never the password.
  @override
  String toString() => 'GeneratedPassword($site, $at)';
}
