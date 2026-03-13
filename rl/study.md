# Literature Survey: RL and Finetuning for Secure Code Generation

*Compiled March 2026*

---

## Table of Contents

1. [The Context Problem: Standalone vs. In-Repo](#1-the-context-problem-standalone-vs-in-repo)
2. [Dataset Formats Used in Practice](#2-dataset-formats-used-in-practice)
3. [How Papers Get Vulnerable vs. Secure Pairs](#3-how-papers-get-vulnerable-vs-secure-pairs)
4. [RL Methods for Code Generation](#4-rl-methods-for-code-generation)
5. [RL Methods Specific to Secure Code](#5-rl-methods-specific-to-secure-code)
6. [Reward Signals](#6-reward-signals)
7. [Security Benchmarks and Datasets](#7-security-benchmarks-and-datasets)
8. [General Code Generation Benchmarks](#8-general-code-generation-benchmarks)
9. [Repo-Level Benchmarks and Context Handling](#9-repo-level-benchmarks-and-context-handling)
10. [Pretrained Code Models and Their Training Data](#10-pretrained-code-models-and-their-training-data)
11. [Instruction Tuning and Data Synthesis](#11-instruction-tuning-and-data-synthesis)
12. [Key Findings and Takeaways](#12-key-findings-and-takeaways)
13. [Gap Analysis: Where Our Work Fits](#13-gap-analysis-where-our-work-fits)
14. [Our Approach: Level 1 and Level 2](#14-our-approach-level-1-and-level-2)
    - [14.1 Level 1: Standalone Function Tasks](#141-level-1-standalone-function-tasks-implemented)
    - [14.2 Level 2: Repo-Level Edit Tasks](#142-level-2-repo-level-edit-tasks-planned)
    - [14.3 Continuous Learning Pipeline](#143-continuous-learning-pipeline)
    - [14.4 Reward Signals: From Pattern Matching to Exploit Verification](#144-reward-signals-from-pattern-matching-to-exploit-verification)
    - [14.5 Red-Team / Blue-Team: Adversarial Reward Scaling](#145-red-team--blue-team-adversarial-reward-scaling)
    - [14.6 Implementation Roadmap](#146-implementation-roadmap)
15. [Scalable Task Extraction: From Repo to Standalone](#15-scalable-task-extraction-from-repo-to-standalone)
    - [15.1 The Core Problem](#151-the-core-problem)
    - [15.2 How Existing Benchmarks Handle Extraction](#152-how-existing-benchmarks-handle-extraction)
    - [15.3 Key Related Work](#153-key-related-work)
    - [15.4 Tools for Build-Free Dependency Analysis](#154-tools-for-build-free-dependency-analysis)
    - [15.5 Proposed Pipeline: LLM + Lightweight Static Analysis](#155-proposed-pipeline-llm--lightweight-static-analysis)
    - [15.6 Test Generation at Scale](#156-test-generation-at-scale)
    - [15.7 Validation Without the Original Repo](#157-validation-without-the-original-repo)
    - [15.8 Open Questions and Future Directions](#158-open-questions-and-future-directions)

---

## 1. The Context Problem: Standalone vs. In-Repo

**The overwhelming consensus across all surveyed papers is: standalone, function-level code.** Nearly every RL and finetuning paper for code generation operates on isolated functions extracted from repositories, not full repo context.

| Approach | Context Level | Examples |
|----------|--------------|---------|
| **Standalone function** (dominant) | Function signature + body, no imports/repo context | SecurityEval, HumanEval, MBPP, SVEN, CyberSecEval, CodeRL, RLTF, StepCoder, SRCode, PurpCode, SmartCoder-R1 |
| **Code prefix / autocomplete** | Partial file, leading code before cursor | CyberSecEval autocomplete mode, Asleep at the Keyboard |
| **Repo-level** | Full repo checkout + issue description | SWE-bench (no security focus, no RL training -- only agentic inference) |
| **Cross-file retrieval** | Function + retrieved snippets from other files | RepoBench, CrossCodeEval, RepoFusion, Repoformer (benchmarks only, not RL training) |

**Key finding from RepoFusion (Shrivastava et al., 2023):** Small models trained *with* repo context outperform **73x larger** models without it. This suggests repo-level context matters enormously -- but nobody has figured out how to do RL with it yet.

**Key finding from Repoformer (Wu et al., 2024):** Indiscriminate retrieval of cross-file context is often "unhelpful or harmful." Selective retrieval brings up to 70% inference speedup without hurting performance.

**Bottom line:** Repo-level RL for code generation is essentially unstudied. SWE-bench is a repo-level benchmark, but approaches to it use agentic methods (tool use, retrieval), not direct RL on generation.

---

## 2. Dataset Formats Used in Practice

### For SFT (Supervised Fine-Tuning)

```jsonl
{"instruction": "Write a function that...", "response": "def foo():\n    ..."}
```

- SafeCoder, WizardCoder, Magicoder (OSS-Instruct), Secure-Instruct
- Typically 10K-100K instruction-response pairs

### For RL (PPO/GRPO)

```
(prompt, unit_tests) -> model generates code -> execute -> reward signal
```

- CodeRL, RLTF, StepCoder, ACECODER, PurpCode, SRCode
- The *training data* is just prompts + test cases. The model generates completions during training.
- Reward comes from execution (pass/fail), static analysis (CodeQL/Semgrep), or both.

### For DPO (Preference Optimization)

```jsonl
{"prompt": "...", "chosen": "secure_code", "rejected": "vulnerable_code"}
```

- PrefGen, SynthCoder
- Preference pairs constructed by: (1) sampling many completions, (2) ranking by test pass rate + security score

### For Security-Specific RL

```
(prompt, vulnerable_code, secure_code) + CWE labels
```

- **SRCode** (2025): 3,289 samples from PrimeVul, 14 CWE categories, **token-level rewards**
- **PurpCode** (2025): 143K prompts, 3 strategies, binary 0/1 rewards from CodeGuru
- **PSSec** (2026): (insecure_script, analysis, repaired_script) triplets, 40K training instances

### Emerging: Triplet Format

- **KodCode** (2025): (question, solution, test) triplets with self-verification via rejection sampling
- Usable for both SFT and RL training

---

## 3. How Papers Get Vulnerable vs. Secure Pairs

| Method | Examples | Scale |
|--------|----------|-------|
| **CVE commit mining** (pre-fix vs post-fix) | DiverseVul (19K vuln functions), BigVul (188K), PrimeVul, SRCode | Large but C/C++ heavy |
| **LLM synthesis + validation** | PurpCode (LLM generates, CodeGuru validates), FormAI (GPT-3.5 generates 112K C programs, formal verification labels) | Very large but noisy |
| **Multi-LLM sampling + ranking** | PrefGen (16 LLMs generate candidates, PageRank ranking), ACECODER (pass-rate based preference) | Medium |
| **Manual CWE prompt crafting** | SecurityEval (121 prompts, 69 CWEs), CyberSecEval, Asleep at the Keyboard (89 scenarios) | Small but high quality |
| **Automated pipeline** | SafeCoder, Secure-Instruct (automated instruction-tuning data synthesis) | Medium |

---

## 4. RL Methods for Code Generation

### 4.1 CodeRL (Le et al., 2022) -- NeurIPS 2022

- **Context:** Standalone functions (APPS, MBPP benchmarks)
- **Format:** Problem description -> code solution, evaluated against unit tests
- **RL method:** Actor-critic architecture. The code-generating LM is the actor; a separately trained critic network predicts functional correctness.
- **Training signal:** Unit test execution results + critic scores
- **Key insight:** Standard SFT ignores execution signals. A "critical sampling strategy" at inference time uses critic scores to guide regeneration.

### 4.2 RLTF (Liu et al., 2023) -- TMLR 2023

- **Context:** Standalone functions (APPS, MBPP)
- **RL method:** Online RL framework, generates training data in real-time during training.
- **Training signal:** Multi-granularity unit test feedback -- not just binary pass/fail but fine-grained signals identifying specific error locations.
- **Key insight:** Fine-grained, location-aware feedback from test execution substantially improves learning over binary signals.

### 4.3 PPOCoder (Shojaee et al., 2023) -- TMLR 2023

- **Context:** Standalone functions
- **RL method:** PPO combined with pretrained code LMs. Task-agnostic and model-agnostic.
- **Training signal:** Dual signal -- execution feedback (functional correctness) + structural alignment.
- **Key insight:** Code has unique sequence-level characteristics (compilability, syntactic correctness) that text-generation objectives miss.

### 4.4 StepCoder (Dou et al., 2024)

- **Context:** Standalone functions (APPS+ with corrected unit tests)
- **RL method:** Two innovations:
  - **CCCS** (Curriculum of Code Completion Subtasks): decomposes long code generation into smaller curriculum-based subtasks
  - **FGO** (Fine-Grained Optimization): masks unexecuted code segments for targeted optimization
- **Training signal:** Compiler feedback as reward
- **Key insight:** Long code generation is hard for RL because exploration space is vast. Breaking into subtasks helps. Optimizing untested code segments is wasteful/harmful.

### 4.5 ACECODER (Zeng et al., 2025) -- ACL 2025

- **Context:** Standalone functions
- **Format:** (question, test-cases) pairs generated from existing code data
- **RL method:** Bradley-Terry reward model + RL with test-case pass rewards. R1-style training from base models.
- **Training signal:** Automated test-case synthesis from existing code, pass-rate-based preference ranking
- **Key insight:** Main bottleneck for code RL is lack of reliable reward data. Automated test-case synthesis solves this at scale. Even 80 RL steps yield >25% improvement on HumanEval+.

### 4.6 Dr. Kernel (Liu et al., 2026)

- **Context:** Standalone GPU kernel functions
- **RL method:** Identified biased policy gradient in GRPO (self-inclusion bias). Proposed TRLOO (Turn-level Reinforce-Leave-One-Out).
- **Training signal:** Profiling-based rewards measuring actual speedup, not just correctness.
- **Key insight:** GRPO has self-inclusion bias. Reward hacking is major risk -- models find shortcuts (trivially correct but slow code). Profiling-based rewards are essential.

### 4.7 MicroCoder (Li et al., 2026)

- **Context:** Standalone competitive programming problems
- **Format:** Tens of thousands of curated problems with LLM-based difficulty filtering.
- **RL method:** GRPO, trained for 300 steps
- **Key insight:** Data difficulty matters enormously. Difficulty-aware curation yields up to 17.2% relative gains. Medium and hard problems provide the most learning signal.

### 4.8 DeepSeek-R1 (DeepSeek-AI, 2025) -- Nature 645

- **RL method:** Pure RL (GRPO) without human-labeled reasoning trajectories
- **Training signal:** Verifiable outcomes (math correctness, code test passing)
- **Key insight:** Reasoning abilities emerge purely from RL without demonstrations. Works best on problems with verifiable solutions (math, code). Distillation transfers reasoning to smaller models.

### 4.9 OpenAI Competitive Programming (El-Kishky et al., 2025)

- **RL method:** General-purpose RL (o1/o3 style)
- **Key insight:** "Scaling general-purpose RL, rather than domain-specific techniques, offers a robust path toward state-of-the-art AI in reasoning domains." o3 achieved IOI gold medal without domain-specific strategies.

---

## 5. RL Methods Specific to Secure Code

### 5.1 SRCode (Quan et al., 2026)

- **Context:** Isolated C/C++ functions from PrimeVul
- **Format:** `<Prompt, code_vulnerable, code_repair>` -- 3,289 samples, 14 CWE categories, 2,500 tasks across three levels (detection, repair, generation)
- **RL method:** PPO with GAE + **token-level rewards** (positive alpha=0.2 for secure patterns, negative distributed uniformly)
- **Training signal:** CodeQL (181 C/C++ security queries) + syntax validation
- **Key innovation:** Fine-grained token-level rewards rather than sequence-level. This is the most important finding for security-specific RL.

### 5.2 PurpCode (Liu et al., 2025)

- **Context:** Standalone Python code
- **Format:** 143K prompts via three strategies (implicit/explicit instructions, code completions, code-editing scenarios)
- **RL method:** DeepSeek-R1-style GRPO with single-step dynamic sampling (adjusts batch size based on learnability fraction). Binary 0-1 rewards.
- **Training signal:** CodeGuru v0.2.4 (131 analyzers) for security + LLM judge for malicious assistance + pytest for correctness
- **Key approach:** Vul2Prompt generates 69K vulnerability-eliciting prompts from CWE descriptions.

### 5.3 SmartCoder-R1 (Yu et al., 2025)

- **Context:** Individual Solidity functions from on-chain contracts
- **Format:** 7,998 SFT samples with `<think>` and `<answer>` blocks
- **RL method:** S-GRPO (Security-aware GRPO) with clipped policy ratio + KL penalty. 8 parallel rollouts.
- **Training signal:** Slither + regex patterns. Weighted: compilation(0.3), security(0.5), format(0.2)
- **Pipeline:** CPT -> L-CoT SFT -> S-GRPO (three-stage)

### 5.4 REAL (Yao et al., 2025)

- **Context:** Standalone functions
- **RL method:** PPO with hybrid reward (security + correctness). LR=1e-6, batch=256, KL penalty=1e-3
- **Training signal:** Custom SSA-based information flow analysis for security + unit tests for correctness
- **Reward formula:** `r_hybrid = alpha * r_quality + (1-alpha) * r_function`
- **Critical finding:** CodeQL was "unexpectedly ineffective" for their use case. Built custom analysis instead.

### 5.5 PSSec (Zhang et al., 2026)

- **Context:** Standalone PowerShell scripts
- **Format:** (insecure_script, analysis_file, repaired_script) -- 40,128 training instances
- **RL method:** PPO with GRPO estimator on 2,437 samples
- **Training signal:** PSScriptAnalyzer (28 security rules, severity 0-3) + F1 scoring

### 5.6 PrefGen (Peng et al., 2025)

- **Context:** Individual Solidity functions from GitHub projects
- **Format:** 7,586 preference pairs from 12,096 candidate implementations from 16 LLMs
- **Training method:** Extended DPO with multi-objective loss combining Pass@k, Gas@k, Secure@k
- **Construction:** PageRank ranking of candidates from multiple LLMs

### 5.7 SVEN (He & Vechev, 2023)

- **Context:** Function-level code completion
- **Training method:** Not SFT but learned continuous prefix vectors with specialized loss terms (no weight modification)
- **Evaluation:** CodeQL for security + HumanEval for correctness
- **Result:** Improved secure generation from 59.1% to 92.3% on CodeGen-2.7B

### 5.8 SafeCoder (He et al., 2024)

- **Context:** Standalone functions
- **Training method:** Pure instruction tuning combining utility + security datasets
- **Evaluation:** CodeQL for security
- **Result:** ~30% security improvement while preserving utility

### 5.9 SecRepair (Islam et al., 2024)

- **Context:** Standalone functions extracted via JOERN from IoT OS repos
- **Format:** Vulnerable-repaired function pairs from VulDeeLocator with NL instructions -- 18,086 entities
- **Training method:** PPO for code comment generation

### 5.10 SFT-to-RL for Vulnerability (Li et al., 2026)

- **RL method:** GRPO with 8 responses per query, group-relative reward normalization
- **Training signal:** LLM-as-judge for root-cause analysis + specification-based rubrics
- **Critical experimental finding:** **GRPO significantly outperforms both SFT and DPO/ORPO** for security tasks. Rejection sampling for SFT data outperforms rationalization (which causes hallucination via ground-truth leakage).

### 5.11 R2Vul

- **Training method:** RLAIF -- Reinforcement Learning from AI Feedback
- **Format:** 18,000 multilingual preference samples
- **Training signal:** AI feedback distinguishing genuine vs. plausible-but-incorrect vulnerability explanations

---

## 6. Reward Signals

| Signal Type | Tools | Papers |
|------------|-------|--------|
| **Static analysis** | CodeQL, Semgrep, Slither, Bandit, PSScriptAnalyzer, CodeGuru | SVEN, SafeCoder, SRCode, PurpCode, SmartCoder-R1 |
| **Unit test execution** | pytest, jest, custom harnesses | CodeRL, RLTF, StepCoder, ACECODER, REAL |
| **Hybrid (static + tests)** | Combined | SRCode, REAL, PSSec, PrefGen |
| **LLM-as-judge** | GPT-4, etc. | R2Vul, PurpCode (malicious assistance check) |
| **Formal verification** | ESBMC | FormAI |
| **Runtime profiling** | Execution speed/memory | Dr. Kernel |
| **Compiler feedback** | Compilation success | StepCoder |
| **Structural alignment** | AST similarity | PPOCoder |

### Fine-Grained vs. Binary Rewards

A consistent finding across papers: **fine-grained rewards dramatically outperform binary pass/fail:**

- **SRCode:** Token-level rewards (marking secure/insecure tokens) >> sequence-level binary
- **RLTF:** Location-aware error feedback >> binary pass/fail
- **StepCoder:** Masking untested code segments >> optimizing everything equally
- **ACECODER:** Pass-rate gradients >> binary test results

### CodeQL Limitations

**REAL (2025) found CodeQL "unexpectedly ineffective"** and built custom SSA-based information flow analysis instead. This matches our own experience with CodeQL detection gaps.

---

## 7. Security Benchmarks and Datasets

### 7.1 SecurityEval (Siddiq & Santos, MSR 2022)

- **Format:** Standalone function completion prompts
- **Context:** Partial Python code (function signatures, docstrings)
- **Evaluation:** Bandit + CodeQL + manual review
- **Size:** 121 prompts covering 69 CWEs (v2.1)
- **Languages:** Python
- **Pairs:** Insecure examples only, no secure versions

### 7.2 CyberSecEval (Meta / Purple Llama, 2023)

- **Format:** Two modes: (a) Autocomplete (code prefix), (b) Instruct (NL description)
- **Evaluation:** Insecure Code Detector (ICD) using static analysis + LLM-as-judge
- **Size:** 100+ prompts per MITRE ATT&CK category, 11 test categories
- **Languages:** C, C++, Python, Java
- **Pairs:** No pairs; measures insecure generation rate
- **Key finding:** More capable models tend to generate more insecure code

### 7.3 LLMSecEval (Tony et al., MSR 2023)

- **Format:** NL prompt -> code generation
- **Evaluation:** Manual review
- **Size:** 150 NL prompts
- **Pairs:** Yes -- each prompt has a secure implementation. Maps to MITRE Top 25 CWEs.

### 7.4 CWEval (Peng et al., 2025)

- **Format:** Code generation tasks testing **both functionality AND security**
- **Evaluation:** Automated unit tests + security tests (outcome-driven)
- **Size:** 119 tasks covering 31 CWEs
- **Languages:** Python, C, C++, Go, JavaScript
- **Key improvement:** Previous benchmarks had "unclear and impractical specifications, failing to assess both functionality and security accurately."

### 7.5 Asleep at the Keyboard (Pearce et al., IEEE S&P 2022)

- **Format:** Scenario-based. 89 scenarios with code prefixes for Copilot completion.
- **Evaluation:** Manual expert review of 1,689 generated programs. ~40% found vulnerable.
- **Languages:** Python, C/C++
- **Significance:** First major study on Copilot security, established methodology.

### 7.6 FormAI (Tihanyi et al., 2023)

- **Format:** Complete standalone C programs, AI-generated
- **Evaluation:** ESBMC (formal verification, eliminates false positives)
- **Size:** 112,000 C programs (51.24% vulnerable)
- **Key distinction:** Largest AI-generated vulnerability dataset. Formal verification rather than pattern matching.

### 7.7 DiverseVul (Chen et al., 2023)

- **Format:** Function-level, extracted from vulnerability-fixing commits
- **Size:** 18,945 vulnerable functions (150 CWEs) + 330,492 non-vulnerable functions from 7,514 commits
- **Languages:** C/C++
- **Pairs:** Yes (pre-fix vulnerable, post-fix non-vulnerable)

### 7.8 BigVul (Chakraborty et al., 2021)

- **Format:** Function-level from vulnerability-fixing commits
- **Size:** ~188K functions
- **Languages:** C/C++
- **Known issues:** Data leakage, label noise, duplication (PrimeVul fixed these)

### 7.9 PrimeVul (Ding et al., 2024, ICSE 2025)

- **Format:** Function-level, improved labeling over BigVul
- **Languages:** C/C++
- **Key finding:** 7B model achieves 68.26% F1 on BigVul but only **3.09% F1 on PrimeVul**, showing previous benchmarks were unrealistically easy due to data leakage.

### 7.10 VulDeePecker (Li et al., 2018, NDSS)

- **Format:** Code gadgets (semantically related code slices), not whole functions
- **Context:** Sliced code following data/control flow at API call sites
- **Significance:** First vulnerability dataset for deep learning

### 7.11 SecLLMHolmes (Ullah et al., IEEE S&P 2024)

- **Format:** 228 code scenarios, 8 investigative dimensions
- **Focus:** Whether LLMs can identify/reason about security bugs
- **Key finding:** GPT-4 fails 26% of time with simple variable renaming -- LLMs are fragile

### 7.12 Secure-Instruct (Li et al., 2025)

- **Format:** Auto-synthesized vulnerable + secure code pairs with task descriptions
- **Evaluation:** CWEBench (93 scenarios, 44 CWEs) and CWEval
- **Result:** Outperforms SafeCoder by 12.6%

---

## 8. General Code Generation Benchmarks

### 8.1 HumanEval (Chen et al., 2021)

- **Format:** Standalone function completion (signature + docstring -> body)
- **Size:** 164 problems, Python only
- **Evaluation:** Unit tests, pass@k
- **JSONL:** `{"task_id": "HumanEval/0", "prompt": "...", "canonical_solution": "...", "test": "...", "entry_point": "..."}`

### 8.2 MBPP (Austin et al., 2021)

- **Format:** NL description + 3 test cases -> complete function
- **Size:** ~1,000 problems, Python only
- **Evaluation:** Unit tests, pass@k

### 8.3 EvalPlus / HumanEval+ / MBPP+ (Liu et al., 2023)

- **Format:** Same as HumanEval/MBPP with massively expanded test suites
- **Size:** HumanEval+ (164 tasks, ~13K tests), MBPP+ (378 tasks, ~35x tests)
- **Key insight:** pass@k drops 19-29% with rigorous tests, showing original benchmarks too lenient

---

## 9. Repo-Level Benchmarks and Context Handling

### 9.1 SWE-bench (Jimenez et al., 2023, ICLR 2024)

- **Format:** Full repo checkout + GitHub issue -> code patch
- **Size:** 2,294 instances from 12 Python repos. SWE-bench Verified: 500 curated.
- **Context:** Fully repo-level. Multi-file changes required.
- **Key finding:** Best model solved only 1.96% at publication. Repo-level is dramatically harder.

### 9.2 RepoBench (Liu et al., 2023)

- **Format:** Python/Java, three tasks (Retrieval, Code Completion, Pipeline)
- **Key insight:** Real-world completion requires multi-file context. HumanEval/MBPP are too simplistic.

### 9.3 CrossCodeEval (Ding et al., 2023, NeurIPS 2023)

- **Format:** Python, Java, TypeScript, C# from real repos
- **Construction:** Static analysis to pinpoint cross-file dependencies
- **Key insight:** Models degrade markedly without cross-file context.

### 9.4 RepoFusion (Shrivastava et al., 2023)

- **Format:** Stack-Repo -- 200 Java repos with three types of repo context
- **Training:** Models trained to incorporate repo context during both training and inference
- **Key finding:** Small model + repo context > 73x larger model without context

### 9.5 Repoformer (Wu et al., 2024, ICML 2024)

- **Method:** Selective retrieval-augmented generation (model decides if retrieval helps)
- **Key finding:** Indiscriminate cross-file retrieval is often "unhelpful or harmful"

---

## 10. Pretrained Code Models and Their Training Data

| Model | Year | Training Data | Context | Key Feature |
|-------|------|--------------|---------|-------------|
| **StarCoder** | 2023 | 1T tokens from The Stack | 8K, infilling | Permissively licensed, PII redaction |
| **DeepSeek-Coder** | 2024 | 2T tokens, **project-level** corpus | 16K, fill-in-blank | First to emphasize project-level training |
| **DeepSeek-Coder-V2** | 2024 | 6T additional tokens, MoE | **128K** | 338 languages, matches GPT-4 Turbo |
| **Qwen2.5-Coder** | 2024 | 5.5T tokens | Large | Data quality/mixing as important as scale |
| **Code Llama** | 2023 | Llama 2 + code SFT | 16K (works to 100K) | 7B Python > Llama 2 70B on code |

---

## 11. Instruction Tuning and Data Synthesis

### 11.1 WizardCoder (Luo et al., 2023, ICLR 2024)

- **Method:** Evol-Instruct adapted for code -- iteratively makes instructions more complex
- **Key insight:** Complex instruction fine-tuning beats all open-source code LLMs

### 11.2 Magicoder (Wei et al., 2023, ICML 2024)

- **Dataset:** 75K synthetic instructions via OSS-Instruct (uses real code snippets as seeds)
- **Key insight:** Grounding synthetic data in real code >> pure LLM generation

### 11.3 OpenCodeInterpreter (Zheng et al., 2024)

- **Dataset:** Code-Feedback -- 68K multi-turn interactions with execution + refinement
- **Key insight:** Open-source 33B matches GPT-4 (83.2 vs 84.2) with execution-based refinement

### 11.4 KodCode (Xu et al., 2025, ACL 2025)

- **Format:** (question, solution, test) triplets with self-verification
- **Construction:** Synthesize questions -> generate solutions with retries -> rewrite formats -> rejection sampling via DeepSeek-R1
- **Key insight:** Triplets with rejection sampling enable both SFT and RL. Beats Qwen2.5-Coder-32B-Instruct.

---

## 12. Key Findings and Takeaways

### RL Methods: What Works

| Method | Status (2025-2026) | Verdict |
|--------|-------------------|---------|
| **GRPO** | Dominant (DeepSeek-R1, PurpCode, SmartCoder-R1, MicroCoder) | Best balance of simplicity and effectiveness. No value network needed. |
| **PPO** | Proven but complex (SRCode, CodeRL, REAL) | Works well especially with token-level rewards. Requires critic network. |
| **DPO** | Simpler but inferior (PrefGen, SynthCoder) | Good when you can construct preference pairs. Outperformed by GRPO for security. |
| **Rejection Sampling** | Widely used as bootstrap (KodCode, Dr. Kernel) | Often used to create SFT data before RL stage. |

**Direct experimental evidence (Li et al., 2026):** GRPO significantly outperforms both SFT and DPO/ORPO for security-related tasks.

### Reward Design: Critical Lessons

1. **Fine-grained >> binary.** Token-level (SRCode), location-aware (RLTF), coverage-masked (StepCoder) all beat simple pass/fail.
2. **Execution feedback is essential.** All successful approaches use test execution, not just static analysis.
3. **CodeQL has gaps.** REAL found it "unexpectedly ineffective." Need hybrid approaches.
4. **Reward hacking is real.** Models find shortcuts (Dr. Kernel). Need profiling-based rewards and rejection sampling.

### The Emerging Best-Practice Pipeline (2025-2026)

```
Stage 1: Curate security-relevant standalone function examples
         (from CVE commits or LLM synthesis + validation)

Stage 2: SFT on instruction-following + security awareness
         (SafeCoder/Secure-Instruct style)

Stage 3: RL (GRPO or PPO) with composite reward:
         - Static analysis (CodeQL/Semgrep/custom) for security
         - Unit tests for correctness
         - Fine-grained, not binary (token-level or location-aware)

Stage 4: Evaluate on held-out benchmarks
         (SecurityEval, CyberSecEval, CWEval)
```

### Context: The Unsolved Problem

- **Every RL paper** uses standalone functions (APPS, MBPP, HumanEval, competitive programming)
- **Repo-level RL** is essentially unstudied
- **RepoFusion** showed training with context beats inference-time retrieval by 73x in model size
- **Nobody has combined** repo-level context + security evaluation + RL training

### Data Quality > Data Quantity

- **MicroCoder:** 3x faster gains with difficulty-curated data
- **KodCode:** Verification pipeline is crucial
- **PrimeVul:** Previous benchmarks were unrealistically easy due to data leakage (68% F1 on BigVul -> 3% F1 on PrimeVul)
- **Magicoder:** Grounding in real code >> pure synthetic generation

---

## 13. Gap Analysis: Where Our Work Fits

### Comparison with Existing Work

| Work | Real CVE | Repo Context | Correctness Tests | Security Check | Vuln/Secure Pairs |
|------|----------|-------------|-------------------|---------------|-------------------|
| SecurityEval | No (synthetic) | No | No | CodeQL | No |
| CyberSecEval | No (synthetic) | Partial | No | ICD | No |
| CWEval (2025) | No (synthetic) | No | Yes | Yes | No |
| SWE-bench | Yes (real issues) | Yes (full repo) | Yes | No | No |
| DiverseVul/BigVul/PrimeVul | Yes (CVE commits) | No (function only) | No | Labels only | Yes |
| SRCode (2025) | Yes (PrimeVul) | No | No | CodeQL | Yes |
| **Our dataset** | **Yes (AI commits)** | **Partial (smart mask)** | **Yes** | **Pattern + CodeQL** | **Yes (3 variants)** |

### Our Unique Contributions

1. **Real AI-generated vulnerable code** from actual production commits (not synthetic CWE examples). Most benchmarks use either synthetic prompts or C/C++ CVEs. We cover JavaScript/TypeScript/Python from AI-assisted commits.

2. **Smart masking is novel.** Nobody else masks only the vulnerability-relevant data flow path while keeping surrounding code visible. This sits between "standalone function" and "full repo context."

3. **Three-variant evaluation.** Broken (fails correctness), insecure (fails security), secure (passes both) -- matches CWEval's philosophy of testing both functionality and security simultaneously.

4. **Vulnhalla-verified ground truth.** LLM-verified vulnerabilities with actual code analysis, not just pattern matching or CWE label assignment.

### Our Dataset Supports Multiple Training Paradigms

| Paradigm | How Our Data Maps |
|----------|------------------|
| **SFT** | `(prompt_tier1, secure_variant)` pairs |
| **DPO** | `(prompt, chosen=secure_variant, rejected=insecure_variant)` preference pairs |
| **GRPO/PPO** | `(prompt_tier1)` as input + `vuln_check` as reward signal |
| **Token-level RL** | Extend `vuln_check` to mark vulnerable line ranges for fine-grained rewards |

### Recommended Next Steps Based on Literature

1. **Adopt GRPO** as the RL algorithm (dominant, simpler than PPO, proven for security by Li et al. 2026)
2. **Implement token-level rewards** (SRCode showed this is critical -- our `vuln_check` already identifies patterns, extend to line-level)
3. **Scale to ~3K+ tasks** (SRCode uses 3,289, PurpCode uses 143K prompts)
4. **Add automated test synthesis** (ACECODER approach -- generate tests from code, not just from descriptions)
5. **Consider hybrid reward** (static analysis + unit tests + LLM judge, as in REAL and PurpCode)
6. **Difficulty-aware curation** (MicroCoder showed medium/hard problems give most learning signal)

---

## 14. Our Approach: Level 1 and Level 2

We decompose the secure code generation problem into two difficulty levels.
Each level has a distinct task format, evaluation method, and training signal,
but they share the same continuous data collection pipeline and reward infrastructure.

### 14.1 Level 1: Standalone Function Tasks (Implemented)

**What it is:** A self-contained, runnable file that preserves the exact same
vulnerability as the original commit but removes all framework dependencies.
The model's job is to generate a single function body given a signature and docstring.

**Task format:**

```
standalone.{js,py}          # Vulnerable (ground truth insecure)
standalone_secure.{js,py}   # Patched version
standalone_broken.{js,py}   # Functionally incorrect version
tests/test_standalone.*     # Unit tests (pass on insecure+secure, fail on broken)
task.json                   # Metadata: CWE, vuln_type, function_signature, etc.
```

**Why Level 1 first:**
- Matches the dominant paradigm in the literature (Section 1) -- every RL paper uses standalone functions
- Execution-based evaluation is straightforward (run tests, run vuln checker)
- Reward signal is clean: functional correctness is binary (tests pass/fail), security is binary (vuln detected/not)
- Fast iteration: no repo checkout, no build system, no dependency resolution
- Proven to work with GRPO/PPO (SRCode, PurpCode, SmartCoder-R1 all use this format)

**Current state (10 tasks, 6 CWE categories):**
- CWE-78: Command injection (2 tasks)
- CWE-79: XSS -- reflected, stored, DOM (3 tasks)
- CWE-89: SQL injection (1 task)
- CWE-22: Path traversal (1 task)
- CWE-918: SSRF (2 tasks)
- CWE-73: File path injection (1 task)
- Languages: JavaScript (9), Python (1)
- Tests: 10/10 passing, Vuln detection: 10/10 insecure=VULN, 10/10 secure=SAFE

**Training use:**

| Paradigm | Level 1 Mapping |
|----------|----------------|
| **SFT** | `(function_signature + docstring, secure_variant_body)` |
| **DPO** | `(prompt, chosen=secure_body, rejected=insecure_body)` |
| **GRPO** | `prompt -> generate N completions -> reward(tests, vuln_check)` |
| **Token-level RL** | Extend vuln_check to return line ranges -> per-token reward shaping |

### 14.2 Level 2: Repo-Level Edit Tasks (Planned)

**What it is:** The vulnerable function lives inside a real repository.
The model must understand cross-file context, framework conventions, and project structure
to produce a correct and secure implementation. This is the unsolved problem (Section 1, Section 9).

**Task format (proposed):**

```
repo/                       # Full or partial repo checkout at the vulnerable commit
  src/...                   # Project source files
  package.json / requirements.txt  # Dependencies
task.json                   # Metadata + vulnerable file path + line range
patch_insecure.diff         # The original vulnerable commit (ground truth)
patch_secure.diff           # A fix that removes the vulnerability
tests/                      # Integration tests that exercise the vulnerable path
build.sh                    # Build/setup script
```

**Key differences from Level 1:**

| Dimension | Level 1 | Level 2 |
|-----------|---------|---------|
| Context | Single file, no deps | Full repo, cross-file deps |
| Input to model | Function signature + docstring | File with `<MASKED>` region + repo context |
| Build | `node file.js` / `python file.py` | `npm install && npm run build` etc. |
| Test | Unit tests on the function | Integration tests, possibly E2E |
| Vuln check | Pattern-based (`vuln_check.py`) | CodeQL on full repo, or exploit-based |
| Difficulty | Standard (matches literature) | Hard (essentially unstudied for RL) |
| Scale target | 3K-10K tasks | 500-1K tasks |

**Why Level 2 matters:**
- RepoFusion showed small models + repo context beat 73x larger models without it
- Real vulnerabilities almost always involve cross-file data flow (source in one file, sink in another)
- No existing RL work addresses this -- it is a genuine research contribution
- SWE-bench showed repo-level is dramatically harder but is the real-world setting

**Open questions for Level 2:**
1. **Context selection:** How much of the repo does the model see? Full checkout is too large for most context windows. Need retrieval or smart windowing (Repoformer's selective retrieval).
2. **Build reliability:** Real repos often have flaky builds, missing env vars, version conflicts. Need sandboxed build environments (Docker/nix).
3. **Reward signal latency:** CodeQL on a full repo takes minutes. Pattern-based vuln_check takes milliseconds. May need tiered reward: fast pattern check during training, CodeQL for validation.
4. **Multi-file edits:** Some fixes require changes in multiple files. The model output format needs to support this (diff format? multi-file generation?).

### 14.3 Continuous Learning Pipeline

A key advantage of our approach over static benchmarks: **we have an automated pipeline
to continuously collect new tasks from GitHub.** This addresses the data staleness and
scale problems that plague existing benchmarks.

**Pipeline:**

```
GitHub AI-assisted commits (Vulnhalla)
    |
    v
generate_tasks.py           # Extract vulnerable functions from commit data
    |
    v
create_level1.py            # LLM rewrites as standalone + generates tests/variants
    |                       # (Level 2: setup repo checkout + integration tests)
    v
vuln_check.py               # Validate: insecure=VULN, secure=SAFE
    |
    v
Quality gate                # Tests pass? Vuln detection correct? Discard failures.
    |
    v
Training pool               # Continuously growing dataset for RL/SFT
```

**Why this matters:**
- **Scale without manual effort.** SRCode has 3,289 tasks. PurpCode has 143K prompts. We can approach these numbers by mining more commits. Vulnhalla continuously scans GitHub AI-assisted PRs -- the supply of new vulnerable code is, unfortunately, growing.
- **Freshness.** Static benchmarks like SecurityEval (2022) and CyberSecEval (2023) become stale. New vulnerability patterns (prompt injection, AI-specific vulns) appear in the wild but not in fixed benchmarks. Our pipeline picks them up naturally.
- **Language diversity.** Most existing datasets are C/C++ heavy (DiverseVul, PrimeVul, BigVul). GitHub AI commits skew toward JavaScript, TypeScript, Python, Go -- the languages where AI coding assistants are most used. This matches the deployment distribution.
- **Difficulty curriculum.** As MicroCoder showed, difficulty-aware data selection matters. We can tag tasks by CWE complexity, function length, number of data flow hops, and build a natural curriculum.
- **Adversarial refresh.** When the model learns to avoid CWE-78 command injection, we can feed it more CWE-78 tasks with novel patterns, or shift to under-represented CWEs. The pipeline supports this without manual intervention.

**Scaling estimates:**
- Vulnhalla currently has ~1,000 verified AI-generated vulnerabilities
- With the Level-1 pipeline (create_level1.py), each vuln produces 1 task in ~30 seconds
- At 80% quality gate pass rate, we can produce ~800 Level-1 tasks from current data
- GitHub adds ~50-100 new AI-assisted vulnerable commits per week (growing)
- Target: 3K+ Level-1 tasks within 1-2 months of continuous collection

### 14.4 Reward Signals: From Pattern Matching to Exploit Verification

The literature (Section 6) shows a clear hierarchy of reward signal quality:

```
Binary pass/fail  <  Fine-grained patterns  <  Static analysis  <  Actual exploitation
     (weakest)                                                        (strongest)
```

We propose a **tiered reward architecture** that gets progressively stronger:

#### Tier 1: Pattern-Based (Current -- `vuln_check.py`)

- **Speed:** ~1ms per check
- **Accuracy:** 100% on our current 10 tasks (both directions)
- **Limitations:** Regex-based, can be fooled by obfuscation or novel patterns
- **Use:** Training-time reward signal for GRPO (needs to be fast)

#### Tier 2: Static Analysis (CodeQL / Semgrep)

- **Speed:** Seconds (standalone) to minutes (repo-level)
- **Accuracy:** Higher coverage of vulnerability patterns, fewer false negatives
- **Limitations:** REAL (2025) found CodeQL "unexpectedly ineffective" for some patterns. High setup cost.
- **Use:** Validation reward, periodic re-scoring of training data

#### Tier 3: Exploit-Based Verification (Proposed)

The strongest signal: **actually exploit the vulnerability.** If the exploit succeeds
on the insecure code and fails on the secure code, the reward signal is unambiguous.

**Per-CWE exploit strategies:**

| CWE | Exploit Method | Verification |
|-----|---------------|-------------|
| CWE-78 (Command Injection) | Craft input with `; echo CANARY` | Check if CANARY appears in output/filesystem |
| CWE-79 (XSS) | Send `<script>` payload via HTTP | Check if payload appears unescaped in response |
| CWE-89 (SQL Injection) | Send `' OR 1=1 --` or `'; DROP TABLE` | Check if query behavior changes / error differs |
| CWE-22 (Path Traversal) | Request `../../etc/passwd` | Check if file outside root is served |
| CWE-918 (SSRF) | Provide `http://169.254.169.254` as URL | Check if request is made to attacker-controlled endpoint |
| CWE-73 (File Path Injection) | Use `../` in username | Check if file is written outside expected directory |

**Implementation approach:**

```python
def exploit_reward(code, task):
    """
    1. Start the standalone in a sandboxed subprocess
    2. Send a crafted malicious request (per CWE type)
    3. Check if the exploit succeeded (canary in output, file written, etc.)
    4. Return: +1 if exploit FAILS (code is secure), -1 if exploit SUCCEEDS (code is vulnerable)
    """
```

**Why exploit-based rewards are better:**
- **Ground truth.** Pattern matching asks "does this code look vulnerable?" Exploitation asks "is this code actually exploitable?" The latter is what matters.
- **Robust to evasion.** A model trained against regex patterns might learn to write vulnerable code that doesn't match the regex. It cannot learn to write exploitable code that is unexploitable.
- **Aligns with attacker model.** The reward directly measures what an adversary would measure.
- **Composable with correctness.** Exploit reward + test pass reward = the exact signal we want: "code that works AND can't be exploited."

**Challenges:**
- **Slower than pattern matching.** Starting a subprocess + sending HTTP requests takes 100ms-1s vs 1ms. May need to batch or use only for validation.
- **Sandbox safety.** Exploit payloads like `rm -rf /` must be contained. Need Docker/namespace isolation.
- **CWE coverage.** Not all CWEs have clean exploit-verify loops. Logic bugs, race conditions, and crypto misuse are hard to exploit programmatically.
- **False negatives.** An exploit failing doesn't guarantee the code is secure -- might just be the wrong payload. Need multiple exploit variants.

**Proposed hybrid reward for training:**

```
reward = w1 * test_pass          # Functional correctness (unit tests)
       + w2 * pattern_safe       # Fast pattern check (vuln_check.py)
       + w3 * exploit_fail       # Exploit verification (when available)

# During GRPO training: use w1=0.3, w2=0.5, w3=0.2 (exploit only on validation batches)
# For final evaluation: use w1=0.3, w2=0.0, w3=0.7 (exploit is ground truth)
```

### 14.5 Red-Team / Blue-Team: Adversarial Reward Scaling

Taking the exploit idea further: instead of fixed exploit scripts, **train a red-team
model to generate exploits** and use it as an adversarial reward signal.

**Concept:**

```
Blue team (code generator):  prompt -> generate secure code
Red team (exploit generator): code + CWE -> generate exploit input
                                              |
                                              v
                                    Execute in sandbox
                                              |
                                     Exploit succeeded?
                                     /              \
                                  Yes                No
                             Blue: -1             Blue: +1
                             Red:  +1             Red:  -1
```

**Why this is powerful:**
- **Self-improving.** As the blue team learns to write more secure code, the red team must find more creative exploits, which in turn forces the blue team to be even more careful. This is a minimax game that drives both models toward the frontier.
- **No fixed benchmark ceiling.** Static benchmarks are solved and forgotten. An adversarial setup keeps generating novel challenges.
- **Aligns with real-world security.** Security is fundamentally adversarial. Training against a static pattern matcher teaches the model to pass the checker, not to be actually secure.

**Connection to literature:**
- **GAN-style training for code** is unexplored in the security domain
- Dr. Kernel (2026) showed reward hacking is a real risk -- adversarial rewards are one mitigation
- Relates to Constitutional AI's approach of using AI feedback to improve AI

**Practical considerations:**
- Red team model can start as a rule-based exploit generator (Tier 3 above), then graduate to LLM-generated exploits
- Need careful sandboxing -- red team literally generates attack payloads
- The minimax objective may be unstable. May need to alternate training or use curriculum (easy exploits first, harder ones later)
- Start with CWEs that have clear exploit/verify loops (injection flaws), expand to harder categories over time

### 14.6 Implementation Roadmap

```
Phase 1 (Current): Level 1 Foundation                          [DONE]
  - 10 standalone tasks across 6 CWE categories
  - Pattern-based vuln check (100% accuracy)
  - Unit tests for all tasks (10/10 passing)
  - 3 variants per task (insecure, secure, broken)

Phase 2: Level 1 Scale-Up                                      [NEXT]
  - Run pipeline on full Vulnhalla dataset (~1K vulnerabilities)
  - Target: 500+ Level-1 tasks
  - Add CWE categories: CWE-502 (deserialization), CWE-20 (input validation),
    CWE-306 (auth bypass), CWE-798 (hardcoded credentials)
  - Expand vuln_check.py patterns for new CWEs
  - Implement exploit-based reward (Tier 3) for injection CWEs

Phase 3: RL Training on Level 1                                 [PLANNED]
  - GRPO with composite reward (tests + vuln_check + exploit)
  - Base model: DeepSeek-Coder-V2 or Qwen2.5-Coder (7B-33B)
  - Token-level reward shaping (extend vuln_check to line ranges)
  - Evaluate on held-out tasks + SecurityEval + CWEval

Phase 4: Level 2 Prototype                                     [PLANNED]
  - Select 50 tasks where the fix requires repo context
  - Set up Docker-based build environments per repo
  - Implement CodeQL-based reward for repo-level evaluation
  - Design context selection strategy (retrieval-augmented or windowed)

Phase 5: Level 2 Scale + Red-Team                              [FUTURE]
  - Scale Level 2 to 200+ repo-level tasks
  - Train red-team exploit generator
  - Adversarial training loop: blue team vs red team
  - Cross-level transfer: does Level 1 training help Level 2 performance?
```

---

## References (Key Papers)

- **CodeRL:** Le et al., "Mastering Code Generation through Pretrained Models and Deep RL", NeurIPS 2022
- **RLTF:** Liu et al., "Reinforcement Learning from Unit Test Feedback", TMLR 2023
- **StepCoder:** Dou et al., "Improve Code Generation with RL from Compiler Feedback", 2024
- **ACECODER:** Zeng et al., "Acing Coder RL via Automated Test-Case Synthesis", ACL 2025
- **Dr. Kernel:** Liu et al., "RL Done Right for Triton Kernel Generations", 2026
- **DeepSeek-R1:** DeepSeek-AI, "Incentivizing Reasoning Capability via RL", Nature 645, 2025
- **SRCode:** Quan et al., "Security-aware RL for Code", 2026
- **PurpCode:** Liu et al., "Security-aware RL for Code LLMs", 2025
- **SmartCoder-R1:** Yu et al., "Security-aware GRPO for Solidity", 2025
- **REAL:** Yao et al., "RL with hybrid security+correctness reward", 2025
- **PSSec:** Zhang et al., "PowerShell Security via RL", 2026
- **SVEN:** He & Vechev, "Security Hardening via Prefix Tuning", 2023
- **SafeCoder:** He et al., "Instruction Tuning for Secure Code Generation", 2024
- **Secure-Instruct:** Li et al., "Automated Pipeline for Security Instruction-Tuning", 2025
- **PrefGen:** Peng et al., "Multi-objective DPO for Solidity", 2025
- **SWE-bench:** Jimenez et al., "Can LMs Resolve Real-World GitHub Issues?", ICLR 2024
- **RepoFusion:** Shrivastava et al., "Training Code Models to Understand Your Repository", 2023
- **Repoformer:** Wu et al., "Selective Retrieval for Repo-Level Code Completion", ICML 2024
- **CWEval:** Peng et al., "Outcome-driven Evaluation on Functionality and Security", 2025
- **SecurityEval:** Siddiq & Santos, MSR 2022
- **CyberSecEval:** Bhatt et al., Meta, 2023
- **PrimeVul:** Ding et al., ICSE 2025
- **DiverseVul:** Chen et al., 2023
- **KodCode:** Xu et al., "Diverse, Challenging, Verifiable Synthetic Dataset for Coding", ACL 2025
- **Magicoder:** Wei et al., "Empowering Code Generation with OSS-Instruct", ICML 2024
- **WizardCoder:** Luo et al., "Empowering Code LLMs with Evol-Instruct", ICLR 2024
- **Asleep at the Keyboard:** Pearce et al., IEEE S&P 2022
- **FormAI:** Tihanyi et al., "AI-Generated and Labeled C Programs", 2023
- **MicroCoder:** Li et al., "Scaling Data Difficulty for RL", 2026
- **AutoBaxBuilder:** ETH Zurich, "LLM-Powered Security Benchmark Generation", 2025 (arxiv 2512.21132)
- **CVE-Factory:** "Multi-Agent CVE-to-Executable-Task Pipeline", 2026 (arxiv 2602.03012)
- **SEC-bench:** "Automated Benchmarking Framework for LLM Security Agents", 2025 (arxiv 2506.11791)
- **FaultLine:** "LLM Agent PoV Test Generation via Source-to-Sink Tracing", 2025 (arxiv 2507.15241)
- **PoCGen:** "LLM + Static + Dynamic Analysis for npm Exploit Generation", 2025 (arxiv 2506.04962)
- **DUALGUAGE:** "Joint Security-Functionality Benchmarking", 2025 (arxiv 2511.20709)
- **QRS:** "LLM-Generated CodeQL Queries + Exploit Synthesis", 2026 (arxiv 2602.09774)
- **Fixturize:** "Fixture Dependency Identification and Synthesis for Tests", 2026 (arxiv 2601.06615)
- **StubCoder:** "Automated Mock/Stub Generation via Evolutionary Algorithm", 2023 (arxiv 2307.14733)
- **GPT-4 Vuln Test Gen:** "GPT-4 for Vulnerability-Witnessing Test Generation", 2025 (arxiv 2506.11559)

---

## 15. Scalable Task Extraction: From Repo to Standalone

*How to extract a vulnerable function from a real GitHub repo and create high-quality
correctness + security tests for it, without needing to set up the original repo?*

This is the central scalability bottleneck. Our Level 1 dataset (10 tasks) was created
manually. To reach 100s-1000s of tasks, we need an automated pipeline.

### 15.1 The Core Problem

Given:
- A GitHub repo URL + commit SHA where a security vulnerability was fixed
- A CodeQL/Snyk/Semgrep alert identifying the vulnerable function and CWE

Produce:
- `standalone.js/py` — A self-contained, runnable file implementing the vulnerable function with mocked dependencies
- `standalone_secure.js/py` — The fixed version
- `tests/test_correctness.js/py` — Functional tests that pass for both variants
- `tests/test_security.js/py` — Exploit tests: VULNERABLE for insecure, SAFE for secure

Constraints:
- **No repo setup**: Cannot install dependencies, build, or run the original project
- **Must be executable**: The standalone must actually run (not just parse)
- **Must be faithful**: The vulnerability must be reproducible in the standalone
- **Must scale**: The pipeline should process a new task in minutes, not hours

### 15.2 How Existing Benchmarks Handle Extraction

| Benchmark | Extraction Method | Executable? | Has Tests? | Scale |
|-----------|------------------|-------------|------------|-------|
| **DiverseVul** (2023) | Function body from git diff | No (raw text) | No | 18,945 functions |
| **PrimeVul** (2024) | Filtered DiverseVul | No (raw text) | No | 6,968 functions |
| **SVEN** (2023) | Manually curated patterns | Partial | No | Small |
| **CyberSecEval** (Meta) | Manually crafted scenarios | Yes | Yes | Small |
| **SecurityEval** (2022) | Manually curated | Yes | Partial | 130 scenarios |
| **CVE-Factory** (2026) | Multi-agent containerized builds | Yes | Yes | 1,000+ |
| **SEC-bench** (2025) | Multi-agent repo setup | Yes | Yes | ~100 |
| **AutoBaxBuilder** (2025) | LLM-generated synthetic tasks | Yes | Yes | ~100 |
| **Our approach** | Manual standalone + mocked deps | Yes | Yes (3-tier) | 10 (so far) |

**Key observation**: No existing benchmark achieves all of (executable, tested,
no-build-required, large-scale). The large-scale ones (DiverseVul, PrimeVul) sacrifice
executability. The executable ones (CVE-Factory, SEC-bench) require building the repo.
This is the gap our pipeline could fill.

### 15.3 Key Related Work

**Most relevant to our extraction problem:**

1. **AutoBaxBuilder** (ETH Zurich, 2025, arxiv 2512.21132): LLM-powered benchmark
   generation producing both correctness and security tests. New task in <2 hours, <$10.
   Generates tasks synthetically rather than extracting from real repos, but the test
   generation methodology is directly applicable.

2. **CVE-Factory** (2026, arxiv 2602.03012): Multi-agent framework transforming CVE
   metadata into fully executable agentic tasks. 1,000+ environments, 14 languages,
   153 repos. Validated 95% solution correctness, 96% environment fidelity. Uses
   containerized builds — the exact bottleneck we want to avoid.

3. **FaultLine** (2025, arxiv 2507.15241): LLM agent workflow for Proof-of-Vulnerability
   test generation. Three steps: (1) source-to-sink tracing, (2) constraint analysis,
   (3) feedback-driven generation. Cross-language (Java, C, C++). 77% improvement over
   baselines. Avoids language-specific static/dynamic analysis — uses LLM reasoning
   to trace data flow. **Directly applicable to our security test generation.**

4. **PoCGen** (2025, arxiv 2506.04962): Generates PoC exploits for npm vulnerabilities.
   Combines LLM understanding + static taint analysis + dynamic validation. 77% success
   on SecBench.js. Average cost $0.02 per exploit. Five of its exploits were incorporated
   into official vulnerability reports. **Directly applicable to our JS-heavy dataset.**

5. **QRS** (2026, arxiv 2602.09774): Three-agent system that generates CodeQL queries,
   validates findings via semantic reasoning, and synthesizes exploits. 90.6% detection
   accuracy on historical CVEs. Found 39 new vulnerabilities in top-100 PyPI packages.
   **Shows LLMs can leverage CodeQL programmatically.**

**Most relevant to dependency isolation:**

6. **StubCoder** (2023, arxiv 2307.14733): Evolutionary algorithm for automatically
   generating mock/stub code. Evaluates on 59 test cases from 13 open-source projects.
   Addresses the exact dependency isolation problem we face.

7. **Fixturize** (2026, arxiv 2601.06615): Identifies functions requiring test fixtures,
   then iteratively synthesizes fixtures. 88-97% accuracy in identifying fixture
   dependencies. 18-43% improvement in test suite pass rates. **Directly relevant to
   our mock generation problem.**

**Test generation quality:**

8. **GPT-4 Vulnerability-Witnessing Tests** (2025, arxiv 2506.11559): Uses VUL4J dataset.
   GPT-4 generates syntactically correct tests 66.5% of the time, but only 7.5% are
   fully semantically correct. **Key finding: LLMs produce useful test templates that
   need minimal manual refinement.** This validates an LLM-assisted approach but shows
   fully automated is hard without a verification loop.

9. **DUALGUAGE** (2025, arxiv 2511.20709): Joint security-functionality benchmarking.
   Pairs each coding task with dual test suites (correctness + security). Uses agentic
   program executor + LLM-based evaluator. **Directly matches our dual test approach.**

### 15.4 Tools for Build-Free Dependency Analysis

A key insight: **for JavaScript and Python, we do NOT need to build the repo** to
perform meaningful static analysis.

| Tool | What It Does | Build Required? | Languages | Best For |
|------|-------------|----------------|-----------|----------|
| **tree-sitter** | Fast AST parsing | No | 40+ | Import/export extraction, function boundary detection |
| **Joern** | Code Property Graph (AST+CFG+PDG) | No | JS, Python, C, Java | Inter-procedural analysis, call graphs |
| **CodeQL extractor** | Full relational DB | No (JS/Python) | Multi | Taint tracking, data flow, type info |
| **Semgrep** | Pattern-based analysis | No | Multi | Quick vulnerability pattern matching |
| **ts-morph** | TypeScript-specific AST | No | TS/JS | Type-aware refactoring |

**Critical insight for CodeQL**: While CodeQL analysis queries typically require a
built database, the CodeQL *extractor* for JavaScript and Python works by simply
parsing source files. This means we can:
1. Run `codeql database create --language=javascript` on a raw checkout (no `npm install`)
2. Query for the vulnerable function's dependencies, call graph, and taint paths
3. Use this information to guide standalone generation

**Joern** is even more lightweight — it creates Code Property Graphs without any build
step and supports inter-procedural analysis. This means we can compute:
- The vulnerable function's call graph (what it calls)
- Its data dependencies (what variables flow into the vulnerable sink)
- The minimal set of code needed to reach the vulnerability from an entry point

### 15.5 Proposed Pipeline: LLM + Lightweight Static Analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SCALABLE TASK EXTRACTION PIPELINE                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Stage 1: LIGHTWEIGHT EXTRACTION (no build, seconds)                │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Input: repo URL + SHA + vulnerable file + function name     │    │
│  │                                                             │    │
│  │ 1. git clone --depth=1 (shallow clone, just the commit)     │    │
│  │ 2. tree-sitter parse: extract function body + imports       │    │
│  │ 3. Joern/CodeQL: compute call graph + dependency signatures │    │
│  │ 4. git diff SHA~1..SHA: extract the security fix            │    │
│  │                                                             │    │
│  │ Output: function source, dependency signatures, git diff    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│  Stage 2: LLM STANDALONE GENERATION (seconds)                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Prompt to LLM:                                              │    │
│  │   "Here is a vulnerable function from a real repo.          │    │
│  │    It depends on: [dependency signatures from Stage 1].     │    │
│  │    The vulnerability (CWE-XX) is: [description].            │    │
│  │    The git diff fixing it is: [diff from Stage 1].          │    │
│  │                                                             │    │
│  │    Generate:                                                │    │
│  │    1. standalone.js - runnable file with mocked deps        │    │
│  │    2. standalone_secure.js - the fixed version              │    │
│  │    Export the function as module.exports."                   │    │
│  │                                                             │    │
│  │ Output: standalone.js, standalone_secure.js                 │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│  Stage 3: LLM TEST GENERATION (seconds)                             │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Correctness tests: from function summary + normal behavior  │    │
│  │   - Must pass for BOTH vulnerable and secure variants       │    │
│  │   - Test functional behavior only, not security properties  │    │
│  │                                                             │    │
│  │ Security tests: from CWE type + taint path + git diff       │    │
│  │   - Mock dangerous sinks (exec, fs.write, fetch, etc.)      │    │
│  │   - Inject attack payloads matching the CWE                 │    │
│  │   - Check if payload reaches the sink unsanitized           │    │
│  │   - Must return VULNERABLE for insecure, SAFE for secure    │    │
│  │                                                             │    │
│  │ Apply PoCGen approach: LLM understanding of vuln description│    │
│  │   + taint path from static analysis + iterative refinement  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│  Stage 4: EXECUTION-BASED VALIDATION (seconds)                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Run correctness tests on standalone.js       → must PASS    │    │
│  │ Run correctness tests on standalone_secure.js → must PASS   │    │
│  │ Run security tests on standalone.js          → must VULN    │    │
│  │ Run security tests on standalone_secure.js   → must SAFE    │    │
│  │                                                             │    │
│  │ If any check fails → feed error back to LLM → retry        │    │
│  │ (FaultLine's feedback-driven generation approach)           │    │
│  │                                                             │    │
│  │ 4-way consistency = quality gate passed                     │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                              │                                      │
│  Stage 5 (optional): CODEQL CROSS-VALIDATION (minutes)              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ For high-confidence subset: run CodeQL on standalone.js     │    │
│  │ Verify it detects the same CWE as the original alert        │    │
│  │ This validates the standalone faithfully reproduces the vuln │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Cost estimate per task** (based on PoCGen and AutoBaxBuilder data):
- Stage 1: ~5 seconds (git clone + parse)
- Stage 2: ~$0.05 (one LLM call with ~4K context)
- Stage 3: ~$0.05 (one LLM call per test type)
- Stage 4: ~2 seconds (execution)
- Stage 5: ~2 minutes (optional CodeQL)
- **Total: ~$0.10-0.15 per task, ~30 seconds without CodeQL**

At this cost, generating 1,000 tasks would take ~$100-150 and a few hours.

### 15.6 Test Generation at Scale

The hardest part of the pipeline is generating **correct** tests. Based on the literature:

**For correctness tests**, the key signals are:
1. **The function summary** (from docstrings, variable names, or LLM inference)
2. **The git diff** — the fix preserves functionality while fixing security, so the
   fixed code implicitly documents what the function should do
3. **Existing repo tests** — if the repo has tests for the vulnerable function, extract
   them as starting points (SEC-bench approach)
4. **Fixturize approach** — identify what the function depends on, generate appropriate
   mocks/fixtures iteratively

**For security tests**, the key signals are:
1. **CWE type** — determines the attack pattern (injection, traversal, SSRF, etc.)
2. **Taint path** — from CodeQL/Joern, the source-to-sink data flow
3. **The git diff** — what the fix added (sanitization, validation, allowlisting)
   tells us exactly what the exploit must bypass
4. **PoCGen approach** — combine LLM understanding of the vulnerability description
   with static taint analysis and dynamic validation

**Verification via differential testing**: A security test is valid if and only if
it produces different results for the vulnerable vs. fixed code. This is a strong
self-checking property that doesn't require external ground truth.

### 15.7 Validation Without the Original Repo

The deepest challenge: how do we know the standalone faithfully reproduces the
original vulnerability? Several complementary approaches:

1. **4-way consistency check** (Stage 4): If correctness tests pass for both variants
   AND security tests differentiate them, the standalone is behaviorally faithful.

2. **CodeQL cross-validation** (Stage 5): Run CodeQL on the standalone. If it detects
   the same CWE, the static analysis properties are preserved. For JS/Python, CodeQL
   can analyze standalone files without building.

3. **Semantic similarity**: Compare the standalone's function body to the original.
   If the vulnerability pattern is preserved (same sink, same source, same data flow),
   the standalone is structurally faithful.

4. **Adversarial validation**: Generate multiple exploit variants (not just one).
   If the standalone is vulnerable to all of them, it's more likely to be faithful.

5. **LLM-as-judge**: Ask an LLM to compare the original function and standalone,
   and verify that the vulnerability is preserved. QRS (2026) shows LLMs can
   perform semantic vulnerability reasoning effectively.

### 15.8 Open Questions and Future Directions

1. **How faithful must the standalone be?** For RL training, we need the vulnerability
   pattern to be present and the tests to be discriminating. We do NOT need the full
   repo behavior to be replicated. The standalone is a "distilled vulnerability" — a
   minimal program that exhibits the security flaw.

2. **Can we use the CodeQL database directly for extraction?** CodeQL databases contain
   complete call graphs, taint paths, and type information. Writing QL queries to
   extract "the minimal subgraph needed to reach the vulnerability from an entry point"
   could automate dependency identification. This is unexplored in the literature.

3. **What about multi-function vulnerabilities?** Some vulnerabilities span multiple
   functions (e.g., a sanitizer in one function is bypassed because another function
   calls it incorrectly). The standalone would need to include both functions. Joern's
   inter-procedural analysis could identify these.

4. **How to handle state-dependent vulnerabilities?** Some vulnerabilities only manifest
   under specific state (e.g., race conditions, session management). These are harder
   to extract into stateless standalones. May need to scope the dataset to
   "stateless" vulnerabilities initially (injection, XSS, SSRF, path traversal).

5. **LLM self-consistency as a quality signal**: If we generate 5 standalones from the
   same function and they all have the same vulnerability pattern, we have higher
   confidence. If they diverge, the extraction is ambiguous and may need human review.

6. **Connection to red-team/blue-team (Section 14.5)**: The test generation pipeline
   could itself be trained via RL — a "red team" LLM generates increasingly clever
   exploit tests, while a "blue team" LLM generates increasingly robust secure code.
   The exploitation tools become the reward signal.
