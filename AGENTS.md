# AGENTS.md — jackin-marketplace

A Claude Code plugin marketplace manifest. Users who add this marketplace via `jackin` or Claude Code will install plugins whose sources are listed in `.claude-plugin/marketplace.json`. **This repo is public.** Every plugin listed here is trusted by every user who loads this marketplace.

Treat every commit to `marketplace.json` as a change to software that will run inside other people's Claude Code sessions with full tool access.

## Threat model

1. **Plugin source URL integrity.** Each plugin's `source.url` points to a git repo. Whoever controls that repo controls what downstream users install when they add the plugin. If a listed URL points to a compromised or hijacked repo, every marketplace user installs the compromised plugin.
2. **Version resolution.** A plugin's declared `version` is metadata; the actual code comes from the source URL. If the source is a bare git URL without a specific ref, Claude Code may resolve to `main` — meaning source-URL content can change between user installs.
3. **Plugin impersonation.** A malicious PR adding a plugin named similarly to a trusted one (`jackin-devv` next to `jackin-dev`) could trick users. Review every plugin addition carefully.
4. **Owner metadata.** `owner.name` in the manifest is a social trust signal. Impersonation of owner name in a future plugin entry would weaken user trust.

## Hard rules (do not break these)

1. **Never add a plugin whose source URL points outside `jackin-project/*`** without a documented trust rationale in the PR body. Third-party plugins are fine in principle, but must be an explicit, reviewed decision — not an accidental addition.
2. **Never change a plugin's `source.url` without treating it as a trust break.** A URL change means "the code users get now comes from somewhere else." Equivalent to changing a Homebrew formula's `url`.
3. **Never commit credentials.** None belong here. The manifest is pure metadata.

## Required pre-commit checks

```bash
# 1. What's staged?
git status --porcelain

# 2. If marketplace.json changed, validate it
if git diff --cached --name-only | grep -qx .claude-plugin/marketplace.json; then
  # Parseable JSON
  python3 -m json.tool .claude-plugin/marketplace.json >/dev/null \
    || { echo "INVALID JSON"; exit 1; }
  # Every plugin source URL must be https and on github.com
  python3 -c "
import json, sys
m = json.load(open('.claude-plugin/marketplace.json'))
for p in m.get('plugins', []):
    url = p.get('source', {}).get('url', '')
    if not url.startswith('https://github.com/'):
        print(f'NON-GITHUB URL: {p[\"name\"]} -> {url}'); sys.exit(1)
"
fi

# 3. Credential scan (defense-in-depth)
git diff --cached --name-only -z | xargs -0 -r \
  grep -l -iE "ghp_|gho_|ghs_|ghr_|github_pat_|BEGIN [A-Z ]*PRIVATE KEY|aws_access_key_id|aws_secret_access_key|bearer [a-z0-9-]{20,}" 2>/dev/null
```

## Upstream dependencies

Every plugin `source.url` is a dependency on another repo's integrity. For each listed plugin, verify periodically that the upstream repo has branch protection and ruleset enforcement:

```bash
for url in $(python3 -c "import json; [print(p['source']['url']) for p in json.load(open('.claude-plugin/marketplace.json'))['plugins']]"); do
  owner_repo=$(echo "$url" | sed 's|https://github.com/||; s|\.git$||')
  echo "$owner_repo: $(gh api repos/$owner_repo/rulesets --jq '.[] | .name' | tr '\n' ',')"
done
```

Expect each listed plugin's source repo to have at least a `protect-main` ruleset.

## Conventions

- Branch naming: `chore/*`, `feat/*`, `fix/*`
- Commit messages follow Conventional Commits
- `main` is the primary branch
- All changes go through PR

## What this does NOT protect against

- A plugin source URL pointing to a ruleset-protected repo whose owner later ships a malicious version — the manifest points at a repo, and the repo's maintainers can do anything within it.
- Claude Code's resolution of bare git URLs to `main` (vs. a pinned tag or commit) — the weaker guarantee lives in the Claude Code client, not here.
- A compromised owner of this marketplace repo (`jackin-project` org owner) adding a poisoned plugin — mitigated by the self-referential ruleset and PR requirement, but not by this AGENTS.md alone.
