#!/usr/bin/env bash
# check-dco.sh BASE HEAD: every commit from BASE to HEAD, merges aside, carries a Signed-off-by line of the Developer
# Certificate of Origin (https://developercertificate.org) with its author's address, as `git commit --signoff` writes
# it: the author's word that they may contribute it under the project's licence. The commits of two
# GitHub Apps can give no such word and are passed over, by their exact addresses: Dependabot's and
# GitHub Actions'. For the Checks workflow's DCO job (CONTRIBUTING.md); run it from the repository
# root.
set -euo pipefail

bots=(
    '49699333+dependabot[bot]@users.noreply.github.com'
    '41898282+github-actions[bot]@users.noreply.github.com'
)

base="$1"
head="$2"
unsigned=0
while read -r sha; do
    email="$(git log -1 --format=%ae "${sha}")"
    subject="$(git log -1 --format=%s "${sha}")"
    if printf '%s\n' "${bots[@]}" | grep -qixF -- "${email}"; then
        echo "dco: ${sha:0:12} is a bot's (${email}): passed over"
        continue
    fi
    if git log -1 --format=%B "${sha}" | git interpret-trailers --parse | grep -i '^signed-off-by:' | grep -qiF "<${email}>"; then
        echo "dco: ${sha:0:12} signed off by its author"
        continue
    fi
    echo "::error title=DCO::Commit ${sha:0:12} (${subject//%/%25}) has no Signed-off-by: line for its author <${email}>"
    unsigned=$((unsigned + 1))
done < <(git rev-list --no-merges --reverse "${base}..${head}")

if ((unsigned)); then
    echo "dco: ${unsigned} commit(s) not signed off. Sign them off and push again:"
    echo "  git rebase --signoff ${base:0:12} && git push --force-with-lease"
    exit 1
fi
echo "dco: ok"
