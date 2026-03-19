# SwarmHawk OSS Launch Checklist

## Technical (do first — one time setup)

- [ ] Create GitHub org: `github.com/hastikdan`
- [ ] Create repo: `hastikdan/swarmhawk-cli` (public)
- [ ] Push the committed code:
  ```bash
  cd swarmhawk_mvp
  git remote add origin https://github.com/hastikdan/swarmhawk-cli.git
  git push -u origin main
  ```
- [ ] Add GitHub repo topics: `security`, `penetration-testing`, `nuclei`, `vulnerability-scanner`, `attack-surface`, `osint`, `python`, `cli`
- [ ] Set repo description: "Autonomous external attack surface assessment — recon → exploit detection → AI synthesis → report"
- [ ] Set repo website: `https://swarmhawk.ai`
- [ ] Enable GitHub Discussions
- [ ] Set up PyPI trusted publishing:
  - Go to pypi.org → "Your projects" → Add project → Publishing
  - Add GitHub publisher: repo `hastikdan/swarmhawk-cli`, workflow `publish.yml`, environment `pypi`
- [ ] Create first GitHub Release: tag `v1.0.0`, title `SwarmHawk v1.0.0 — open-source release`
  - This triggers the PyPI publish workflow automatically
- [ ] Verify `pip install swarmhawk` works after publish

---

## Launch Day (pick a Tuesday–Thursday)

**Morning (9am ET):**
- [ ] Post Hacker News Show HN → copy from `promotion/hacker_news.md`
- [ ] Post to r/netsec → copy from `promotion/reddit.md`
- [ ] Post to r/hacking → copy from `promotion/reddit.md`
- [ ] Post to r/cybersecurity → copy from `promotion/reddit.md`
- [ ] Post to r/Python → copy from `promotion/reddit.md`
- [ ] Post Twitter/X thread → copy from `promotion/social.md`
- [ ] Post LinkedIn → copy from `promotion/social.md`
- [ ] Post in ProjectDiscovery Discord #tools-showcase → copy from `promotion/social.md`
- [ ] Submit Product Hunt (schedule for same day) → copy from `promotion/product_hunt.md`

**Same day — reply actively:**
- [ ] Respond to every HN comment within the first 2 hours
- [ ] Respond to Reddit comments
- [ ] Reply to Twitter mentions

---

## Week 1 (after launch)

- [ ] Email tl;dr sec → copy from `promotion/newsletters.md`
- [ ] Email Unsupervised Learning → copy from `promotion/newsletters.md`
- [ ] Email Securibee → copy from `promotion/newsletters.md`
- [ ] Submit to SANS ISC → copy from `promotion/newsletters.md`
- [ ] Submit tip to The Hacker News → copy from `promotion/newsletters.md`
- [ ] Open PR to nuclei-templates repo → copy from `promotion/nuclei_pr.md`
- [ ] Publish blog post on swarmhawk.ai → copy from `promotion/blog_post.md`
- [ ] Cross-post blog to dev.to
- [ ] Cross-post blog to Medium (security tag)

---

## Ongoing

- [ ] Reply to every GitHub issue within 24h (builds community trust)
- [ ] Merge first external PR quickly (signals "active project")
- [ ] Post weekly update on Twitter/LinkedIn for 4 weeks ("500 stars!", "first community PR merged", etc.)
- [ ] Add "swarmhawk" tag to any Nuclei template you contribute upstream

---

## Star milestones to post about

- 100 ⭐ — post "100 stars, thank you"
- 500 ⭐ — write a blog post about what the community has contributed
- 1,000 ⭐ — Product Hunt relaunch / press outreach
