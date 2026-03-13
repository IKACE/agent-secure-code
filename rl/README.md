# RL for Secure Code Generation with `verl`

Train Qwen2.5-Coder-0.5B-Instruct with GRPO to generate code that is both **correct** and **secure**, using test-execution rewards from 318 real-world vulnerability tasks.

## Overview

| Component | Detail |
|-----------|--------|
| Model | `Qwen/Qwen2.5-Coder-0.5B-Instruct` |
| Algorithm | GRPO (Group Relative Policy Optimization) via `verl` |
| Dataset | 318 function-level tasks (292 JS, 26 Python) with correctness + security tests |
| Reward | 0.0 (fails correctness) → 0.5 (correct but vulnerable) → 1.0 (correct + secure) |
| Infrastructure | Docker (`verlai/verl:vllm011.latest`), single GPU |

## Repo Layout

```
rl/
├── scripts/
│   ├── prepare_secure_code_dataset.py   # Convert task dirs → verl parquet
│   ├── run_qwen25_coder_grpo.sh         # Launch GRPO training
│   ├── prepare_humaneval_dataset.py     # (legacy) HumanEval PoC dataset
│   └── run_qwen25_coder_ppo.sh         # (legacy) PPO with random reward
├── rewards/
│   ├── secure_code_reward.py            # Test-execution reward function
│   └── random_binary_reward.py          # (legacy) Random reward for smoke tests
├── data/
│   ├── secure_code/                     # Generated train/val parquet files
│   └── humaneval/                       # (legacy) HumanEval parquet files
├── checkpoints/                         # Saved model checkpoints
└── README.md
```

## Recipe

### Step 0: Container Setup (one-time)

Create and start the Docker container:

```bash
docker create \
  --gpus all \
  --net=host \
  --shm-size=10g \
  --cap-add=SYS_ADMIN \
  -v /raid/yilegu:/workspace/verl \
  --name yilegu_verl_exec \
  --entrypoint bash \
  verlai/verl:vllm011.latest \
  -lc 'sleep infinity'

docker start yilegu_verl_exec
docker exec -it yilegu_verl_exec bash
```

Install dependencies inside the container:

```bash
# verl
cd /root/verl && pip install -e .

# Node.js (needed to run JS test cases in the reward function)
apt-get update && apt-get install -y nodejs

# Dataset prep
pip install pandas pyarrow
```

### Step 1: Prepare the Dataset

```bash
cd /workspace/verl/agent-secure-code/rl
python3 scripts/prepare_secure_code_dataset.py
```

This reads 318 task directories from `dataset/data/tasks/` and writes:

- `data/secure_code/train.parquet` (270 rows)
- `data/secure_code/val.parquet` (48 rows)

Each row contains:

| Field | Content |
|-------|---------|
| `prompt` | Chat-format message (`[{"role": "user", "content": ...}]`) from `prompt.md` |
| `data_source` | `"secure_code"` — used for reward routing |
| `ground_truth` | Content of `standalone_secure.js/py` |
| `extra_info` | `task_id`, `task_dir`, `language`, `setup_code`, `func_signature` |

### Step 2: Run GRPO Training

```bash
cd /workspace/verl/agent-secure-code/rl
export PYTHONPATH=/root/verl:$PYTHONPATH
export CUDA_VISIBLE_DEVICES=1

# Path rewriting: host paths in parquet → container paths for test execution
export TASK_DIR_REWRITE_FROM=/raid/yilegu
export TASK_DIR_REWRITE_TO=/workspace/verl

bash scripts/run_qwen25_coder_grpo.sh
```

Override defaults via environment variables or extra CLI args:

```bash
# Use a different model
MODEL_PATH=/models/Qwen2.5-Coder-0.5B-Instruct bash scripts/run_qwen25_coder_grpo.sh

# More epochs, different GPU count
bash scripts/run_qwen25_coder_grpo.sh trainer.total_epochs=3 trainer.n_gpus_per_node=2

# Enable reward debug logging (first N calls)
REWARD_DEBUG_LOG_COUNT=10 bash scripts/run_qwen25_coder_grpo.sh
```

### Step 3: Check Results

Training metrics are logged to the console. Key metrics to watch:

```
critic/score/mean   — average reward across the batch
critic/score/max    — best reward in the batch (0.5 = correct, 1.0 = correct+secure)
actor/pg_loss       — policy gradient loss (non-zero = model is learning)
actor/grad_norm     — gradient magnitude (non-zero = parameter updates happening)
```

Checkpoints are saved to `checkpoints/rl_security/qwen25_coder_05b_secure_code_grpo/`.

## How the Reward Function Works

The reward function (`rewards/secure_code_reward.py`) evaluates each model-generated solution:

```
Model generates response
        │
        ▼
Extract code from markdown fences (if present)
        │
        ▼
Assemble full file: setup_code + model_output
        │
        ▼
Write to temp file
        │
        ▼
Run test_correctness.js ──── FAIL ──→ reward = 0.0
        │
       PASS
        │
        ▼
Run test_security.js ─────── FAIL ──→ reward = 0.5  (correct but vulnerable)
        │
       PASS
        │
        ▼
                              reward = 1.0  (correct + secure)
```

Each task directory under `dataset/data/tasks/` contains:
- `prompt.md` — the coding prompt with setup code and function signature
- `standalone.js` — a correct but vulnerable reference implementation
- `standalone_secure.js` — the correct and secure reference
- `tests/test_correctness.js` — functional correctness tests
- `tests/test_security.js` — exploit simulation tests (e.g., checks if `Math.random()` is used instead of `crypto.randomBytes()`)

## GRPO Training Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| `algorithm.adv_estimator` | `grpo` | No critic needed; uses within-group reward variance |
| `actor_rollout_ref.rollout.n` | `4` | 4 samples per prompt — needed for GRPO to have reward variance |
| `data.train_batch_size` | `16` | 16 prompts × 4 samples = 64 rollouts per step |
| `data.max_prompt_length` | `1024` | Prompts average ~540 tokens, max ~1187 |
| `data.max_response_length` | `512` | Model generates function body + exports |
| `algorithm.kl_ctrl.kl_coef` | `0.001` | Light KL penalty to stay near the base model |

### Why GRPO over PPO

GRPO computes advantages from the relative ranking of rewards within each prompt's sample group, rather than requiring a learned value function (critic). This means:
- No critic model to train (saves memory and compute)
- Works well with sparse binary/ternary rewards like ours
- Requires `n > 1` samples per prompt for reward variance

### Why Instruct model, not base

The base `Qwen2.5-Coder-0.5B` generates incoherent text for these prompts — all rewards are 0.0, meaning zero gradient signal. The Instruct variant can occasionally produce valid code, giving GRPO the reward variance it needs to learn.

## Verified Results (1 epoch, 16 steps, ~3 min on 1× B200)

- Non-zero rewards appear at ~25% of steps
- `score/max` reached **1.0** (correct + secure) and **0.5** (correct but vulnerable)
- `pg_loss` and `grad_norm` are non-zero when reward variance exists
- Validation accuracy: ~1% of held-out tasks pass (starting point for RL)

## Legacy: HumanEval PPO Smoke Test

The original PoC used HumanEval with a random binary reward to validate the verl pipeline:

```bash
python3 scripts/prepare_humaneval_dataset.py
bash scripts/run_qwen25_coder_ppo.sh
```

This is still useful for debugging verl setup issues without the Node.js dependency.

## References

- verl: https://github.com/verl-project/verl
- Qwen2.5-Coder: https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct
- GRPO paper: https://arxiv.org/abs/2402.03300
- Study notes: `study.md` (literature survey on RL for secure code generation)
