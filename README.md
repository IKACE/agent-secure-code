# agent-secure-code-repo

Scripts and tools for studying security in AI-generated code.

## Structure

```
crawling/       # GitHub commit crawling scripts
analysis/       # SARIF/CodeQL diff analysis and vulnerability attribution
pipeline/       # End-to-end evaluation pipelines (CodeQL DB creation, Vulnhalla batch runs, result summarization)
dataset/        # Task and prompt generation for benchmark datasets
evaluation/     # Model evaluation and result analysis
vulnhalla/      # Vulnhalla security benchmark (git submodule)
```

## Setup

```bash
# Clone with submodules
git clone --recurse-submodules <repo-url>

# Or initialize submodules after clone
git submodule update --init --recursive

# Copy and fill in environment variables
cp .env.example .env
```
