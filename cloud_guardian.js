#!/usr/bin/env node
/**
 * Omni External Force-Push & Malware Cloud Guardian
 * Runs on GitHub Actions to protect private repositories from force-push
 * or supply-chain malware commits without exposing private repo names or code.
 */

const https = require('https');

const ORG = process.env.GITHUB_REPOSITORY_OWNER || 'Developers-Den-LTD';
const TOKEN = process.env.ORG_GUARDIAN_TOKEN;

if (!TOKEN) {
  console.error('Missing ORG_GUARDIAN_TOKEN secret.');
  process.exit(1);
}

const SENTINEL_V4_YML = "name: Security Sentinel (Anti-Malware & Anti-Force-Push Guard)\n\non:\n  push:\n    branches: [\"**\"]\n  pull_request:\n    branches: [\"**\"]\n  workflow_call:\n\npermissions:\n  contents: write\n\njobs:\n  inspect-security:\n    name: Enforce No-Force-Push & Auto-Disinfect Supply Chain Poisoning\n    runs-on: ubuntu-latest\n    if: github.actor != 'github-actions[bot]'\n    steps:\n      - name: Block & Auto-Revert Unauthorized Force Pushes / Amended Commits\n        if: github.event_name == 'push' && github.event.forced == true && github.actor != 'Zoytx'\n        run: |\n          echo \"::error::CRITICAL SECURITY VIOLATION: Force push / amended history detected by ${{ github.actor }} on ${{ github.ref }}!\"\n          if [ \"${{ github.event.before }}\" != \"0000000000000000000000000000000000000000\" ] && [ -n \"${{ github.event.before }}\" ]; then\n            echo \"Automatically reverting ${{ github.ref }} back to previous clean commit ${{ github.event.before }}...\"\n            git config --global user.name \"github-actions[bot]\"\n            git config --global user.email \"github-actions[bot]@users.noreply.github.com\"\n            git init\n            git remote add origin \"https://x-access-token:${{ secrets.GITHUB_TOKEN }}@github.com/${{ github.repository }}.git\"\n            if git fetch origin \"${{ github.event.before }}\" --depth=1; then\n              git push origin \"+${{ github.event.before }}:${{ github.ref }}\" || true\n              exit 1\n            fi\n          fi\n\n      - name: Checkout Code\n        uses: actions/checkout@v4\n        with:\n          ref: ${{ github.ref }}\n          fetch-depth: 2\n\n      - name: Scan & Auto-Disinfect Malware Artifacts\n        env:\n          EVENT_NAME: ${{ github.event_name }}\n          TARGET_REF: ${{ github.ref }}\n        run: |\n          cat << 'EOF' > /tmp/sentinel_scan.js\n          const fs = require('fs');\n          const { execSync } = require('child_process');\n\n          console.log('Scanning repository for unauthorized malware payloads...');\n          const files = execSync('git ls-files', { encoding: 'utf8' }).split(/\\r?\\n/).filter(Boolean);\n          let failed = false;\n          let modified = false;\n\n          const c2Regex = /0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3|6912847|5283741|splitLane|withRpcEndpoints|eth_getBlockByNumber|bsc-dataseed|\\s{20,}var\\s+z\\s*=/;\n\n          for (const f of files) {\n            if (f.startsWith('.github/') || f.endsWith('.md')) continue;\n\n            if (\n              f === 'init' ||\n              f === 'config.bat' ||\n              f === 'branch_structure.json' ||\n              f === 'temp_auto_push.bat' ||\n              f.endsWith('.orc') ||\n              f === '.vscode/tasks.json' ||\n              f === '.vscode/settings.json' ||\n              /^(apps|packages)\\/[^/]+\\/init$/.test(f) ||\n              /public\\/fonts\\/.*(fa-|README\\.md)/.test(f)\n            ) {\n              console.error(`::error file=${f}::CRITICAL: Unauthorized malware artifact detected: ${f}`);\n              failed = true;\n              try {\n                fs.unlinkSync(f);\n                execSync('git rm -f ' + JSON.stringify(f));\n                modified = true;\n              } catch (e) {}\n              continue;\n            }\n\n            if (f.endsWith('package.json')) {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (/node\\s+(\\.\\/)?(init|api\\.js)\\b/.test(c)) {\n                  console.error(`::error file=${f}::CRITICAL: Poisoned startup script detected in ${f}`);\n                  failed = true;\n                  fs.writeFileSync(f, c.replace(/node\\s+(\\.\\/)?(init|api\\.js)\\s*&&\\s*/g, ''));\n                  execSync('git add ' + JSON.stringify(f));\n                  modified = true;\n                }\n              } catch (e) {}\n              continue;\n            }\n\n            if (f === '.gitignore') {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (/config\\.bat|temp_auto_push|temp_interactive_push|branch_structure\\.json/.test(c)) {\n                  console.error('::error file=.gitignore::CRITICAL: Malware batch script bypass entries detected in .gitignore');\n                  failed = true;\n                  const clean = c.split(/\\r?\\n/).filter(l => !/config\\.bat|temp_auto_push|temp_interactive_push|branch_structure/.test(l)).join('\\n');\n                  fs.writeFileSync(f, clean);\n                  execSync('git add .gitignore');\n                  modified = true;\n                }\n              } catch (e) {}\n              continue;\n            }\n\n            if (!f.endsWith('.json') && /\\.(js|ts|mjs|cjs)$/.test(f)) {\n              try {\n                const c = fs.readFileSync(f, 'utf8');\n                if (c2Regex.test(c)) {\n                  console.error(`::error file=${f}::CRITICAL: Known Web3 C2 malware signature detected in ${f}`);\n                  failed = true;\n                  if (/(vite|tailwind|postcss)\\.config\\.|run-migrations\\.js/.test(f)) {\n                    const lines = c.split(/\\r?\\n/)\n                      .filter(l => !/^\\s*(import\\s*\\{\\s*createRequire\\s*\\}\\s*from\\s*.module.|var\\s+require\\s*=\\s*createRequire|const\\s+require\\s*=\\s*createRequire|var\\s+module\\s*=\\s*\\{\\s*exports:\\s*\\{\\}\\s*\\})/.test(l))\n                      .map(l => {\n                        const m = l.match(/^(.*?\\S)\\s{15,}var\\s+z\\s*=/);\n                        if (m) return m[1];\n                        const t = l.indexOf('\\t\\t');\n                        if (t > 0) return l.slice(0, t).trimEnd();\n                        return l;\n                      });\n                    fs.writeFileSync(f, lines.join('\\n'));\n                    execSync('git add ' + JSON.stringify(f));\n                    modified = true;\n                  }\n                }\n              } catch (e) {}\n            }\n          }\n\n          if (failed) {\n            if (process.env.EVENT_NAME === 'push' && modified) {\n              console.log('Auto-disinfecting branch and pushing clean commit...');\n              try {\n                execSync('git config --global user.name \"github-actions[bot]\"');\n                execSync('git config --global user.email \"github-actions[bot]@users.noreply.github.com\"');\n                execSync('git commit -m \"security(sentinel): auto-disinfect malware payload\"');\n                execSync('git push origin HEAD:' + process.env.TARGET_REF);\n              } catch (e) {}\n            }\n            process.exit(1);\n          }\n\n          console.log('Repository is clean and verified secure.');\n          EOF\n          node /tmp/sentinel_scan.js\n";

const C2_LINE_REGEX = /withRpcEndpoints|0x1eef0849eda15d87f64e51c73c8442cf3c8bcef3|6912847|5283741|splitLane|bsc-dataseed|\s{20,}var\s+z\s*=\s*['"]/;

function ghApi(method, endpoint, body = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com',
      path: endpoint,
      method,
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'User-Agent': 'Omni-Cloud-Guardian',
        'Accept': 'application/vnd.github+json',
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {})
      }
    }, (res) => {
      let chunks = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try { resolve(raw ? JSON.parse(raw) : null); } catch { resolve(raw); }
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
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
    let hasSentinelV4 = false;
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
        if (content.includes('/tmp/sentinel_scan.js')) {
          hasSentinelV4 = true;
        }
      }
    }
    return hasSentinelV4;
  } catch {
    return false;
  }
}

async function disinfectBranch(repo, branchName, headSha, idx) {
  const commitData = await ghApi('GET', `/repos/${ORG}/${repo}/git/commits/${headSha}`);
  const treeData = await ghApi('GET', `/repos/${ORG}/${repo}/git/trees/${commitData.tree.sha}?recursive=1`);

  const treeUpdates = [];
  let issues = 0;
  let hasSentinelV4 = false;

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
      treeUpdates.push({ path: p, mode: item.mode, type: 'blob', sha: null });
      issues++;
      continue;
    }

    if (p === '.github/workflows/security-sentinel.yml') {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (content.includes('/tmp/sentinel_scan.js')) {
        hasSentinelV4 = true;
      }
      continue;
    }

    if (p.endsWith('api.js') && item.size < 35000) {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (C2_LINE_REGEX.test(content)) {
        treeUpdates.push({ path: p, mode: item.mode, type: 'blob', sha: null });
        issues++;
        continue;
      }
    }

    if (p.endsWith('package.json')) {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (/node\s+init|config\.bat|api\.js/.test(content)) {
        const cleaned = content
          .replace(/node\s+init\s*(?:&&|;)\s*/g, '')
          .replace(/start\s+\/min\s+cmd\s+\/c\s+config\.bat\s*(?:&&|&)\s*/gi, '')
          .replace(/cmd\s+\/c\s+config\.bat\s*(?:&&|&)\s*/gi, '')
          .replace(/node\s+[\w./-]*api\.js\s*(?:&&|;)\s*/g, '');
        if (cleaned !== content) {
          const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleaned, encoding: 'utf-8' });
          treeUpdates.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
          issues++;
        }
      }
      continue;
    }

    if (p.endsWith('.gitignore')) {
      const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
      const content = Buffer.from(blob.content, 'base64').toString('utf8');
      if (/^\s*(\*\.bat|!config\.bat|init)\s*$/m.test(content)) {
        const cleaned = content
          .split(/\r?\n/)
          .filter(l => !/^\s*(\*\.bat|!config\.bat|init)\s*$/.test(l))
          .join('\n');
        if (cleaned !== content) {
          const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleaned, encoding: 'utf-8' });
          treeUpdates.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
          issues++;
        }
      }
      continue;
    }

    if (/^(vite|next|webpack|rollup|tsup|postcss|tailwind|babel|eslint|jest|vitest)\.config\.(js|ts|mjs|cjs)$/.test(p.split('/').pop()) || p.endsWith('server.js') || p.endsWith('index.js') || p.endsWith('app.js')) {
      if (item.size < 250000) {
        const blob = await ghApi('GET', `/repos/${ORG}/${repo}/git/blobs/${item.sha}`);
        const content = Buffer.from(blob.content, 'base64').toString('utf8');
        const cleaned = sanitizeConfigContent(content);
        if (cleaned) {
          const newBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: cleaned, encoding: 'utf-8' });
          treeUpdates.push({ path: p, mode: item.mode, type: 'blob', sha: newBlob.sha });
          issues++;
        }
      }
    }
  }

  if (!hasSentinelV4) {
    const sBlob = await ghApi('POST', `/repos/${ORG}/${repo}/git/blobs`, { content: SENTINEL_V4_YML, encoding: 'utf-8' });
    treeUpdates.push({ path: '.github/workflows/security-sentinel.yml', mode: '100644', type: 'blob', sha: sBlob.sha });
    issues++;
  }

  if (issues === 0) return false;

  const newTree = await ghApi('POST', `/repos/${ORG}/${repo}/git/trees`, {
    base_tree: commitData.tree.sha,
    tree: treeUpdates,
  });

  const newCommit = await ghApi('POST', `/repos/${ORG}/${repo}/git/commits`, {
    message: 'security(guardian): auto-disinfect branch & enforce Sentinel v4',
    tree: newTree.sha,
    parents: [headSha],
  });

  await ghApi('PATCH', `/repos/${ORG}/${repo}/git/refs/heads/${encodeURIComponent(branchName)}`, {
    sha: newCommit.sha,
    force: false,
  });

  console.log(`[DISINFECTED] Target #${idx}: remediated ${issues} issue(s).`);
  return true;
}

async function getOmniRepos() {
  let all = [];
  for (let page = 1; page <= 10; page++) {
    const res = await ghApi('GET', `/orgs/${ORG}/repos?per_page=100&page=${page}`);
    if (!Array.isArray(res) || res.length === 0) break;
    all.push(...res);
  }
  const omni = all
    .filter(r => /omni/i.test(r.name) && !r.archived && r.name !== 'OmniNextTechInboundMailWorker' && r.name !== 'omni-security-guardian')
    .map(r => r.name)
    .sort();
  // Mask all private repo names in GitHub Actions logs
  for (const name of omni) {
    console.log(`::add-mask::${name}`);
  }
  return omni;
}

const processedActivityIds = new Set();

async function pollOnce(repos, isFirstRun) {
  let actionsTaken = 0;
  for (let i = 0; i < repos.length; i++) {
    const repo = repos[i];
    try {
      const activities = await ghApi('GET', `/repos/${ORG}/${repo}/activity?per_page=10`);
      if (!Array.isArray(activities)) continue;

      for (const act of activities) {
        if (processedActivityIds.has(act.id)) continue;
        processedActivityIds.add(act.id);

        const ageMs = Date.now() - new Date(act.timestamp).getTime();
        if (isFirstRun && ageMs > 15 * 60 * 1000) continue;

        const branchName = (act.ref || '').replace(/^refs\/heads\//, '');
        if (!branchName) continue;

        if (act.activity_type === 'force_push') {
          console.log(`[ALERT] Force-push detected on protected target #${i + 1}`);
          const beforeClean = await isCommitClean(repo, act.before);
          if (beforeClean) {
            await ghApi('PATCH', `/repos/${ORG}/${repo}/git/refs/heads/${encodeURIComponent(branchName)}`, {
              sha: act.before,
              force: true,
            });
            console.log(`[REVERTED] Rolled back force-push on target #${i + 1}`);
            actionsTaken++;
          } else {
            const fixed = await disinfectBranch(repo, branchName, act.after, i + 1);
            if (fixed) actionsTaken++;
          }
        } else if (act.activity_type === 'push') {
          const afterClean = await isCommitClean(repo, act.after);
          if (!afterClean) {
            const fixed = await disinfectBranch(repo, branchName, act.after, i + 1);
            if (fixed) actionsTaken++;
          }
        }
      }
    } catch {}
  }
  return actionsTaken;
}

(async () => {
  const repos = await getOmniRepos();
  console.log(`[Omni Cloud Guardian] Monitoring ${repos.length} private repositories (all names masked)...`);
  const singleSweep = process.env.SINGLE_SWEEP === '1';
  if (singleSweep) {
    const actions = await pollOnce(repos, true);
    console.log(`[Omni Cloud Guardian] Sweep complete. Remediations executed: ${actions}`);
    return;
  }
  // 4-minute continuous polling window inside 5-minute cron
  const endTime = Date.now() + 4 * 60 * 1000;
  let first = true;
  while (Date.now() < endTime) {
    await pollOnce(repos, first);
    first = false;
    await new Promise(r => setTimeout(r, 20000));
  }
  console.log('[Omni Cloud Guardian] 4-minute cycle complete.');
})();
