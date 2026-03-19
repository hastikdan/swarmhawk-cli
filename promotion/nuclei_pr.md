# Nuclei Templates PR — ProjectDiscovery

Submit a PR to: https://github.com/projectdiscovery/nuclei-templates

**Goal:** Get SwarmHawk mentioned/cited inside the official Nuclei templates repo. ProjectDiscovery will see it, their community will see it.

---

## PR approach

The cleanest contribution: a workflow YAML file that shows how to use Nuclei templates with SwarmHawk's validation pipeline. Submit to the `helpers/` or `workflow/` directory.

**File to create in the PR:** `workflows/swarmhawk-web-assessment.yaml`

```yaml
id: swarmhawk-web-assessment
info:
  name: SwarmHawk Web Assessment Workflow
  author: swarmhawk-ai
  description: |
    Curated Nuclei template workflow for external web application assessment.
    Designed for use with SwarmHawk (github.com/hastikdan/swarmhawk) but
    works standalone. Prioritises confirmed/critical templates to reduce
    false positives in automated pipelines.
  tags: workflow,web,assessment,automation

workflows:
  - template: technologies/tech-detect.yaml
  - template: exposures/configs/git-config.yaml
  - template: exposures/configs/env-file.yaml
  - template: exposures/configs/phpinfo.yaml
  - template: exposures/panels/
  - template: cves/2024/
    tags: critical,rce
  - template: cves/2023/
    tags: critical
  - template: misconfiguration/
  - template: vulnerabilities/generic/
  - template: ssl/
  - template: network/detection/
```

**PR title:** `workflows: add SwarmHawk web assessment workflow`

**PR body:**

Adds a curated workflow YAML for external web application assessment, optimised for automated pipelines.

This workflow is the template set used by SwarmHawk (https://github.com/hastikdan/swarmhawk), an open-source Python CLI that wraps nuclei with subdomain enumeration, CVE/EPSS enrichment, and AI synthesis. We run this workflow as part of the exploit detection phase and apply confidence thresholds to filter noise before generating client reports.

The template selection prioritises:
- Confirmed/critical CVE templates
- Exposed panel and config file detection
- SSL/TLS misconfiguration checks
- Technology fingerprinting (for context in reports)

Tested against ProjectDiscovery's test environments and our own infrastructure.

---

## Alternative: submit a blog post to ProjectDiscovery's blog

They have a community blog at blog.projectdiscovery.io. Pitch a post:

**Title:** Building an automated pentest pipeline with Nuclei, subfinder, and Python

**Pitch email:** contact@projectdiscovery.io

Hi PD team,

I built SwarmHawk — an open-source Python CLI that orchestrates subfinder, httpx, and nuclei into a full external assessment pipeline with AI synthesis and tamper-evident audit logs.

I'd love to write a technical post for the ProjectDiscovery blog showing how we integrate the toolchain and the specific Nuclei template selection/validation approach we use.

GitHub: https://github.com/hastikdan/swarmhawk

Would that be a fit for the blog?

[Your name]
