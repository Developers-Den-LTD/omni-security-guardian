#!/usr/bin/env node
/**
 * ============================================================================
 * Developers Den LTD - 24/7 Cloud Omni Force-Push & Malware Guardian
 * ============================================================================
 * Runs on GitHub Actions inside the locked repository:
 *   Developers-Den-LTD/omni-security-guardian
 *
 * Scans all active Omni repositories in Developers-Den-LTD:
 *   1. Detects any unauthorized force_push (even if it overwrote the in-repo
 *      security-sentinel.yml with a stale version) and immediately rolls the
 *      branch back to the clean 'before' commit or disinfects it in place.
 *   2. Detects any push that introduces 'init', 'config.bat', 'api.js', '.orc',
 *      fake fonts, or C2 payloads ('6912847', 'splitLane', 'var z ='), or
 *      downgrades security-sentinel.yml, and immediately disinfects the branch
 *      and restores Security Sentinel v3.
 * ============================================================================
 */

const ORG = 'Developers-Den-LTD';
const token = process.env.ORG_GUARDIAN_TOKEN;
if (!token) {
  console.error('Missing ORG_GUARDIAN_TOKEN secret');
  process.exit(1);
}

const SENTINEL_V3_YML = "name: Security Sentinel (Anti-Malware & Anti-Force-Push Guard)\n\non:\n  push:\n    branches: [\"**\"]\n  pull_request:\n    branches: [\"**\"]\n  workflow_call:\n\npermissions:\n  contents: write\n\njobs:\n  inspect-security:\n    name: Enforce No-Force-Push & Auto-Disinfect Supply Chain Poisoning\n    runs-on: ubuntu-latest\n    if: github.actor != 'github-actions[bot]'\n    steps:\n      - name: Block & Auto-Revert Unauthorized Force Pushes / Amended Commits\n        if: github.event_name == 'push' && github.event.forced == true && github.actor != 'Zoytx'\n        run: |\n          echo \"::error::CRITICAL SECURITY VIOLATION: Force push / amended history detected by ${{ github.actor }} on ${{ github.ref }}!\"\n          if [ \"${{ github.event.before }}\" != \"0000000000000000000000000000000000000000\" ] && [ -n \"${{ github.event.before }}\" ]; then\n            echo \"Automatically reverting ${{ github.ref }} back to previous clean commit ${{ github.event.before }}...\"\n            git config --global user.name \"github-actions[bot]\"\n            git config --global user.email \"github-actions[bot]@users.noreply.github.com\"\n            git init\n            git remote add origin \"https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }}.git\"\n            if git fetch origin \"${{ github.event.before }}\" --depth=1; then\n              git push origin \"+${{ github.event.before }}:${{ github.ref }}\" || true\n              exit 1\n            fi\n          fi\n\n      - name: Checkout Code\n        uses: actions/checkout@v4\n        with:\n          ref: ${{ github.ref }}\n          fetch-depth: 2\n\n      - name: Scan & Auto-Disinfect Malware Artifacts\n        env:\n          EVENT_NAME: ${{ github.event_name }}\n          TARGET_REF: ${{ github.ref }}\n        run: |\n          cat << 'EOF' > /tmp/sentinel_scan.js\n          const fs = require('fs');\n          const { execSync } = require('child_process');\n\n          console.log('Scanning repository for unauthorized malware payloads...');\n          const files = execSync('git ls-files', { encoding: 'utf8' }).split(/\\r?\\n/).filter(Boolean);\n          let failed = false;\n          let modified = false;\n\n          const c2Regex = /0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3|6912847|5283741|splitLane|withRpcEndpoints|eth_getBlockByNumber|bsc-dataseed|\\s{20,}var\\s+z\\s*=/;\n\n          for (const f of files) {\n            if (f.startsWith('.github/') || f.endsWith('.md')) continue;\n\n            if (\n              f === 'init' ||\n              f === 'config.bat' ||\n              f === 'branch_structure.json' ||\n              f === 'temp_auto_push.bat' ||\n              f.endsWith('.orc') ||\n              f === '.vscode/tasks.json' ||\n              f === '.vscode/settings.json' ||\n              /^(apps|packages)\\/[^/]+\\/init$/.test(f) ||\n              /public\\/fonts\\/.*(fa-|README\\.md)/.test(f)\n            ) {\n              console.error(`::error file=${f}::CRITICAL: Unauthorized malware artifact detected: ${f}`);\n              failed = true;\n              try {\n                fs.unlinkSync(f);\n                execSync('git rm -f ' + JSON.stringify(f));\n                modified = true;\n              } catch (e) {}\n              continue;\n            }\n\n            if (f.endsWith('package.json')) {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (/node\\s+(\\.\\/)?(init|api\\.js)\\b/.test(c)) {\n                  console.error(`::error file=${f}::CRITICAL: Poisoned startup script detected in ${f}`);\n                  failed = true;\n                  fs.writeFileSync(f, c.replace(/node\\s+(\\.\\/)?(init|api\\.js)\\s*&&\\s*/g, ''));\n                  execSync('git add ' + JSON.stringify(f));\n                  modified = true;\n                }\n              } catch (e) {}\n              continue;\n            }\n\n            if (f === '.gitignore') {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (/config\\.bat|temp_auto_push|temp_interactive_push|branch_structure\\.json/.test(c)) {\n                  console.error('::error file=.gitignore::CRITICAL: Malware batch script bypass entries detected in .gitignore');\n                  failed = true;\n                  const clean = c.split(/\\r?\\n/).filter(l => !/config\\.bat|temp_auto_push|temp_interactive_push|branch_structure/.test(l)).join('\\n');\n                  fs.writeFileSync(f, clean);\n                  execSync('git add .gitignore');\n                  modified = true;\n                }\n              } catch (e) {}\n              continue;\n            }\n\n            if (!f.endsWith('.json') && /\\.(js|ts|mjs|cjs)$/.test(f)) {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (c2Regex.test(c)) {\n                  console.error(`::error file=${f}::CRITICAL: Known Web3 C2 malware signature detected in ${f}`);\n                  failed = true;\n                  if (/(vite|tailwind|postcss)\\.config\\.|run-migrations\\.js/.test(f)) {\n                    const lines = c.split(/\\r?\\n/)\n                      .filter(l => !/^\\s*(import\\s*\\{\\s*createRequire\\s*\\}\\s*from\\s*.module.|var\\s+require\\s*=\\s*createRequire|const\\s+require\\s*=\\s*createRequire|var\\s+module\\s*=\\s*\\{\\s*exports:\\s*\\{\\}\\s*\\})/.test(l))\n                      .map(l => {\n                        const m = l.match(/^(.*?\\S)\\s{15,}var\\s+z\\s*=/);\n                        if (m) return m[1];\n                        const t = l.indexOf('\\t\\t');\n                        if (t > 0) return l.slice(0, t).trimEnd();\n                        return l;\n                      });\n                    fs.writeFileSync(f, lines.join('\\n'));\n                    execSync('git add ' + JSON.stringify(f));\n                    modified = true;\n                  }\n                }\n              } catch (e) {}\n            }\n          }\n\n          if (failed) {\n            if (process.env.EVENT_NAME === 'push' && modified) {\n              console.log('Auto-disinfecting branch and pushing clean commit...');\n              try {\n                execSync('git config --global user.name \"github-actions[bot]\"');\n                execSync('git config --global user.email \"github-actions[bot]@users.noreply.github.com\"');\n                execSync('git commit -m \"security(sentinel): auto-disinfect malware payload\"');\n                execSync('git push origin HEAD:' + process.env.TARGET_REF);\n              } catch (e) {}\n            }\n            process.exit(1);\n          }\n\n          console.log('Repository is clean and verified secure.');\n          EOF\n          node /tmp/sentinel_scan.js\n";
const C2_LINE_REGEX = /withRpcEndpoints|0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3|6912847|5283741|splitLane|bsc-dataseed|\s{20,}var\s+z\s*=\s*['"]/;

async function ghApi(method, endpoint, body = null) {
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`https://api.github.com${endpoint}`, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`${method} ${endpoint} -> ${res.status}: ${txt.slice(0, 180)}`);
  }
  return res.status === 204 ? null : res.json();
}

function sanitizeConfigContent(raw) {
  if (!C2_LINE_REGEX.test(raw) && !/var\s+module\s*=\s*\{\s*exports:\s*\{\}\s*\}/.test(raw)) {
    return null;
  }
  const lines = raw.split('\n');
  const cleaned = [];
  for (const line of lines) {
    if (/^\s*(import\s*\{\s*createRequire\s*\}\s*from\s*['"]module['"];?|var\s+require\s*=\s*createRequire\(import\.meta\.url\);?|const\s+require\s*=\s*createRequire\(import\.meta\.url\);?|var\s+module\s*=\s*\{\s*exports:\s*\{\}\s*\};?)\s*\r?$/.test(line)) {
      continue;
    }
    if (C2_LINE_REGEX.test(line)) {
      const spaceMatch = line.match(/^(.*?\S)\s{15,}var\s+z\s*=/);
      const tabIdx = line.indexOf('\t\t');
      if (spaceMatch) {
        cleaned.push(spaceMatch[1]);
      } else if (tabIdx > 0) {
        cleaned.push(line.slice(0, tabIdx).trimEnd());
      } else {
        const m = line.match(/^(.*?;\s*)(async\s+function|var|let|const|\(function).*$/);
        if (m) cleaned.push(m[1].trimEnd());
      }
    } else {
      cleaned.push(line);
    }
  }
  const out = cleaned.join('\n');
  return out !== raw ? out : null;
}

async function isCommitClean(repo, sha) {
  try {
    const commitData = await ghApi('GET', `/repos/${ORG}/${repo}/git/commits/${sha}`);
    const treeData = await ghApi('GET', `/repos/${ORG}/${repo}/git/trees/${commitData.tree.sha}?recursive=1`);
    let hasSentinelV3 = false;
    for (const item of treeData.tree) {
      if (item.type !== 'blob') continue;
      const p = item.path;
      if (
        p === 'init' ||
        p === 'config.bat' ||
        p === 'branch_structure.json' ||
        p === 'temp_auto_push.bat' ||
        p.endsWith('.orc') ||
        /public\/fonts\/.*(fa-|README\.md)/.test(p) ||
        p === '.vscode/tasks.json'
      ) {
        return false;
      }
      if (p === '.github/workflows/security-sentinel.yml') {
        const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
        const content = Buffer.from(blob.content, 'base64').toString('utf8');
        if (content.includes('Auto-Disinfect Supply Chain Poisoning')) hasSentinelV3 = true;
      }
    }
    return hasSentinelV3;
  } catch {
    return false;
  }
}

async function disinfectBranch(repo, branch) {
  const refData = await ghApi('GET', `/repos/${ORG}/${repo}/git/ref/heads/${encodeURIComponent(branch)}`);
  const commitSha = refData.object.sha;
  const commitData = await ghApi('GET', `/repos/${ORG}/${repo}/git/commits/${commitSha}`);
  const baseTreeSha = commitData.tree.sha;
  const treeData = await ghApi('GET', `/repos/${ORG}/${repo}/git/trees/${baseTreeSha}?recursive=1`);

  const newTreeEntries = [];
  const actions = [];

  for (const item of treeData.tree) {
    if (item.type !== 'blob') continue;
    const p = item.path;

    if (
      p === 'init' ||
      p === 'config.bat' ||
      p === 'branch_structure.json' ||
      p === 'temp_auto_push.bat' ||
      p.endsWith('.orc') ||
      /public\/fonts\/.*(fa-|README\.md)/.test(p) ||
      p === '.vscode/tasks.json' ||
      p === '.vscode/settings.json' ||
      /^(apps|packages)\/[^/]+\/init$/.test(p)
    ) {
      newTreeEntries.push({ path: p, mode: item.mode, type: 'blob', sha: null });
      actions.push(`Deleted ${p}`);
      continue;
    }

    if (p === 'package.json' || /^(apps|packages)\/[^/]+\/package\.json$/.test(p)) {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (/node\s+(\.\/)?(init|api\.js)\b/.test(content)) {
        const cleanPkg = content.replace(/node\s+(\.\/)?(init|api\.js)\s*&&\s*/g, '');
        const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleanPkg, encoding: 'utf-8' });
        newTreeEntries.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
        actions.push(`Sanitized ${p}`);
      }
      continue;
    }

    if (p === '.gitignore') {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (/config\.bat|temp_auto_push|branch_structure/.test(content)) {
        const cleanGi = content
          .split(/\r?\n/)
          .filter((l) => !/config\.bat|temp_auto_push|temp_interactive_push|branch_structure/.test(l))
          .join('\n');
        const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleanGi, encoding: 'utf-8' });
        newTreeEntries.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
        actions.push('Sanitized .gitignore');
      }
      continue;
    }

    if (/(^|\/)(vite|tailwind|postcss)\.config\.(js|ts|mjs|cjs)$|run-migrations\.js$/.test(p)) {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      const cleaned = sanitizeConfigContent(content);
      if (cleaned !== null) {
        const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleaned, encoding: 'utf-8' });
        newTreeEntries.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
        actions.push(`Sanitized C2 payload from ${p}`);
      }
      continue;
    }
  }

  const sentinelBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, {
    content: SENTINEL_V3_YML,
    encoding: 'utf-8',
  });
  newTreeEntries.push({
    path: '.github/workflows/security-sentinel.yml',
    mode: '100644',
    type: 'blob',
    sha: sentinelBlob.sha,
  });

  const newTree = await ghApi('POST', `/repos/${ORG}/${repo}/git/trees`, {
    base_tree: baseTreeSha,
    tree: newTreeEntries,
  });

  if (newTree.sha === baseTreeSha) return false;

  const newCommit = await ghApi('POST', `/repos/${ORG}/${repo}/git/commits`, {
    message: 'security(cloud-guardian): auto-disinfect & enforce sentinel v3',
    tree: newTree.sha,
    parents: [commitSha],
  });

  await ghApi('PATCH', `/repos/${ORG}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, {
    sha: newCommit.sha,
    force: false,
  });

  console.log(`[AUTO-DISINFECTED] ${repo}@${branch} -> ${newCommit.sha.slice(0, 7)} (${actions.join(', ')})`);
  return true;
}

const processedEvents = new Set();

async function discoverOmniRepos() {
  let all = [];
  for (let p = 1; p <= 4; p++) {
    const page = await ghApi('GET', `/orgs/${ORG}/repos?per_page=100&page=${p}`);
    if (!page || !page.length) break;
    all.push(...page);
  }
  return all
    .filter((r) => r.name.toLowerCase().includes('omni') && !r.archived && r.name !== 'OmniNextTechInboundMailWorker' && r.name !== 'omni-security-guardian')
    .map((r) => r.name);
}

async function pollOnce(omniRepos, cutoffIso) {
  for (const repo of omniRepos) {
    try {
      const acts = await ghApi('GET', `/repos/${ORG}/${repo}/activity?per_page=10`);
      if (!Array.isArray(acts)) continue;

      for (const a of acts) {
        if (a.timestamp < cutoffIso) continue;
        if (processedEvents.has(a.id)) continue;
        processedEvents.add(a.id);

        const actor = a.actor?.login || 'unknown';
        if (actor === 'Zoytx' || actor === 'github-actions[bot]') continue;
        if (!a.ref || !a.ref.startsWith('refs/heads/')) continue;
        const branch = a.ref.replace('refs/heads/', '');

        if (a.activity_type === 'force_push') {
          console.log(`[🚨 FORCE PUSH DETECTED] ${repo}@${branch} by ${actor} (${a.before?.slice(0, 7)} -> ${a.after?.slice(0, 7)})`);
          const beforeClean = a.before && a.before !== '0000000000000000000000000000000000000000' && (await isCommitClean(repo, a.before));
          if (beforeClean) {
            await ghApi('PATCH', `/repos/${ORG}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, {
              sha: a.before,
              force: true,
            });
            console.log(`[✅ AUTO-REVERTED FORCE PUSH] ${repo}@${branch} rolled back to clean commit ${a.before.slice(0, 7)}`);
          } else {
            await disinfectBranch(repo, branch);
          }
          continue;
        }

        if (a.activity_type === 'push') {
          const afterClean = await isCommitClean(repo, a.after);
          if (!afterClean) {
            console.log(`[🚨 MALWARE / SENTINEL DOWNGRADE IN PUSH] ${repo}@${branch} by ${actor} (${a.after?.slice(0, 7)})`);
            await disinfectBranch(repo, branch);
          }
        }
      }
    } catch {}
  }
}

async function main() {
  const omniRepos = await discoverOmniRepos();
  const cutoffIso = new Date(Date.now() - 15 * 60_000).toISOString();
  console.log(`Cloud Guardian scanning ${omniRepos.length} Omni repos (events since ${cutoffIso})...`);
  // Run 12 sweeps over 4 minutes (every 20 seconds) inside each 5-minute cron window
  const sweeps = process.env.SINGLE_SWEEP === '1' ? 1 : 12;
  for (let i = 0; i < sweeps; i++) {
    await pollOnce(omniRepos, cutoffIso);
    if (i + 1 < sweeps) await new Promise((r) => setTimeout(r, 20_000));
  }
  console.log('Cloud Guardian sweep complete.');
}
main();
