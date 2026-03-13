# RL Security PoC with `verl`

This repo is a minimal proof-of-concept PPO pipeline for code-generation RL with `verl` and `Qwen/Qwen2.5-Coder-0.5B`.

The initial setup is intentionally simple:

- Task: generate a Python function implementation from a coding prompt
- Dataset: HumanEval converted into `verl` parquet files
- Reward: simulated binary reward (`0.0` or `1.0`) returned randomly
- Trainer: PPO via `python -m verl.trainer.main_ppo`

This gets the end-to-end RL loop working first. Once this runs, you can replace the reward with a real secure-code evaluator without changing the rest of the pipeline shape.

## Why HumanEval for the PoC

HumanEval is a clean first coding dataset because it is small, public, easy to load from Hugging Face, and already structured as function-completion tasks.

Other coding datasets worth trying later:

- `mbpp`: larger and more instruction-like
- `codeparrot/apps`: broader and harder, but heavier
- `deepmind/code_contests`: larger-scale competitive programming

For a first `verl` PPO smoke test, HumanEval keeps the data path small and debuggable.

## Repo Layout

- `scripts/prepare_humaneval_dataset.py`: downloads and converts HumanEval to `verl` parquet
- `rewards/random_binary_reward.py`: custom reward function for `verl`
- `scripts/run_qwen25_coder_ppo.sh`: launches PPO with a small PoC config
- `data/`: generated parquet files
- `outputs/`: training outputs and checkpoints

## 1. Prepare the dataset

Inside the running `verl` container:

```bash
cd /workspace/verl/agent-secure-code/rl
python3 scripts/prepare_humaneval_dataset.py
```

This writes:

- `data/humaneval/train.parquet`
- `data/humaneval/val.parquet`

The parquet rows include:

- `prompt`
- `ground_truth`
- `data_source`
- `task_id`
- `extra_info`

`extra_info` carries the HumanEval metadata you will want later when swapping the random reward for a real code evaluator.

## 2. Run PPO

Inside the same container:

```bash
cd /workspace/verl/agent-secure-code/rl
bash scripts/run_qwen25_coder_ppo.sh
```

The launcher defaults to:

- model: `Qwen/Qwen2.5-Coder-0.5B`
- rollout backend: `vllm`
- GPUs per node: `1`
- reward function: local random binary reward

Override the model path if you have a local snapshot:

```bash
MODEL_PATH=/models/Qwen2.5-Coder-0.5B bash scripts/run_qwen25_coder_ppo.sh
```

## 3. Start your existing container

Your container was created with:

```bash
docker create \
  --gpus all \
  --net=host \
  --shm-size="10g" \
  --cap-add=SYS_ADMIN \
  -v .:/workspace/verl \
  --name yilegu_verl \
  verlai/verl:vllm011.latest
```

If it is not running yet:

```bash
docker start yilegu_verl
docker exec -it yilegu_verl bash
```

I could not verify Docker from this environment because access to `/var/run/docker.sock` is blocked here.

## Notes on `verl` compatibility

This PoC follows the current `verl` quickstart pattern:

- custom reward functions are provided through `custom_reward_function.path` and `custom_reward_function.name`
- PPO is launched through `verl.trainer.main_ppo`
- the dataset uses the standard `prompt` field and includes `data_source` so reward routing works cleanly

## Next upgrades after the smoke test

1. Replace the random reward with secure-code execution plus unit-test or sandbox checks.
2. Move from HumanEval to MBPP or APPS for more training rows.
3. Add reward decomposition:
   correctness, exploitability, insecure API usage, taint-flow flags, policy compliance.
4. Compare PPO against GRPO or RLOO once the evaluator is real.

## References

- `verl` quickstart: https://verl.readthedocs.io/en/latest/start/quickstart.html
- `verl` repository: https://github.com/verl-project/verl
- HumanEval dataset: https://huggingface.co/datasets/openai/openai_humaneval
