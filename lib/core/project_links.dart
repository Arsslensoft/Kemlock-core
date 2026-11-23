/// Where the app points people for the project itself (openspec: add-fdroid-release).
library;

/// The published source. A placeholder until the repo is public and named
/// (add-security-docs, task 6.3).
const sourceRepository = 'https://github.com/kemlock/kemlock';

/// The page that says how to check a build against the source, in the repo.
final reproducibleBuildsPage = Uri.parse('$sourceRepository/blob/main/docs/reproducible-builds.md');

/// The free build's "Support Kemlock" page. A placeholder until the owner
/// gives its address (add-fdroid-release, task 6.2).
final supportPage = Uri.parse('$sourceRepository#support');
