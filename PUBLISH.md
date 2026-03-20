# SwarmHawk Publishing Playbook

Complete step-by-step guide to publishing the MVP.

---

## Step 1 — GitHub (do this today, 10 minutes)

### 1a. Create the repository

1. Go to github.com → New repository
2. Name: `swarmhawk` (under org `swarmhawk-ai` or your personal account)
3. Visibility: **Private** (until you're ready to go public)
4. DO NOT initialize with README (you have one already)

### 1b. Push the code

```bash
cd swarmhawk_mvp/
git init
git add .
git commit -m "feat: SwarmHawk MVP v1.0.0 — RECON + EXPLOIT + SYNTHESIS + REPORT"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/swarmhawk.git
git push -u origin main
```

### 1c. Add repository secrets (for CI)

Settings → Secrets and variables → Actions → New secret:
- `ANTHROPIC_API_KEY` — for integration tests with real AI synthesis

### 1d. Branch protection

Settings → Branches → Add rule for `main`:
- ✓ Require status checks to pass before merging
- ✓ Require the Tests workflow to pass

---

## Step 2 — Test on a real machine (this week)

```bash
# On any machine with Python 3.11+
git clone https://github.com/YOUR_USERNAME/swarmhawk.git
cd swarmhawk
pip install -e .

# Run mock demo (no tools needed)
swarmhawk scan --target testdomain.com --mock
# → Opens report in reports/ directory

# Install real tools for live scanning
# macOS:
brew install subfinder httpx nuclei

# Linux (requires Go):
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Run against YOUR OWN domain first (always test on yourself before customers)
swarmhawk scan --target yourdomain.com
```

---

## Step 3 — First design partner engagement

### Create scope ledger

```bash
swarmhawk scope new \
  --customer "Customer Corp" \
  --domain customer-corp.com \
  --authorized-by "Jane Smith, CISO, Customer Corp" \
  --days 30 \
  --output scopes/customer_corp.json
```

Send `scopes/customer_corp.json` to customer for review.
Have legal review the authorization agreement BEFORE running any scan.

### Run engagement

```bash
ANTHROPIC_API_KEY=sk-ant-... \
swarmhawk scan \
  --target customer-corp.com \
  --scope scopes/customer_corp.json \
  --output ./engagements/customer-corp-2026-03/
```

Deliver `*.html` report to customer. Charge $5,000–15,000.

---

## Step 4 — PyPI (when you have 3+ customers, ~month 2)

Makes it `pip install swarmhawk` from anywhere.

```bash
# Register at pypi.org
# Create API token: Account Settings → API tokens

# Build distribution packages
pip install build twine
python -m build
# Creates: dist/swarmhawk-1.0.0.tar.gz and dist/swarmhawk-1.0.0-py3-none-any.whl

# Test upload to TestPyPI first
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ swarmhawk

# Upload to real PyPI
twine upload dist/*
```

After: `pip install swarmhawk` works for anyone worldwide.

---

## Step 5 — Docker Hub (when customers want isolated runs)

```bash
# Build
docker build -t swarmhawk:1.0.0 .
docker tag swarmhawk:1.0.0 swarmhawkai/swarmhawk:latest

# Test
docker run -v $(pwd)/reports:/app/reports swarmhawk:1.0.0 scan --target testdomain.com --mock

# Push (requires docker login + Docker Hub account)
docker login
docker push swarmhawkai/swarmhawk:1.0.0
docker push swarmhawkai/swarmhawk:latest
```

After: customers run `docker pull swarmhawkai/swarmhawk` — no Python required.

---

## Step 6 — Public GitHub release (when ready to go public)

1. Change repo visibility: Settings → Danger Zone → Make public
2. Create release: Releases → Draft new release
   - Tag: `v1.0.0`
   - Title: `SwarmHawk MVP v1.0.0`
   - Attach: `dist/swarmhawk-1.0.0.tar.gz`
   - Mark as: Pre-release (until production-hardened)

3. Add topics to repo: `cybersecurity`, `penetration-testing`, `ai`, `vulnerability-scanner`

4. Submit to awesome lists:
   - awesome-security (github.com/sbilly/awesome-security)
   - awesome-pentest (github.com/enaqx/awesome-pentest)

---

## Publishing Checklist

Before any public release:

- [ ] Legal review of ToS and authorized use agreement
- [ ] Export control counsel review (offensive security tools)
- [ ] All tests passing (pytest tests/ -v)
- [ ] No API keys or customer data in git history
- [ ] ANTHROPIC_API_KEY not hardcoded anywhere
- [ ] `reports/` and `scopes/` in .gitignore and confirmed clean
- [ ] README updated with accurate installation steps
- [ ] CHANGELOG.md created
- [ ] LICENSE file added (proprietary or source-available)

---

## Cost Summary

| Service | Cost | When |
|---------|------|------|
| GitHub private repo | Free | Now |
| GitHub Actions CI | Free (2,000 min/mo) | Now |
| PyPI | Free | Month 2 |
| Docker Hub | Free (1 private repo) | Month 2 |
| Domain: swarmhawk.ai | ~$138/2yr | Now |
| VPS for scans (Hetzner CX21) | ~$6/mo | Month 1 |

**Total to first paying customer: ~$150**

