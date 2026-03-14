#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXTRA_ARGS=("$@")

MODEL_PATH="${MODEL_PATH:-,}"
TRAIN_FILE="${TRAIN_FILE:-data/humaneval/train.parquet}"
VAL_FILE="${VAL_FILE:-data/humaneval/val.parquet}"
N_GPUS="${N_GPUS:-1}"
ROLLOUT_TP="${ROLLOUT_TP:-1}"
EXPERIMENT_NAME="${EXPERIMENT_NAME:-qwen25_coder_05b_random_reward_ppo}"
PROJECT_NAME="${PROJECT_NAME:-rl_security_poc}"
VLLM_CUDAGRAPH_MODE="${VLLM_CUDAGRAPH_MODE:-PIECEWISE}"

export HYDRA_FULL_ERROR=1
export VLLM_ATTENTION_BACKEND="${VLLM_ATTENTION_BACKEND:-FLASHINFER}"

python3 -m verl.trainer.main_ppo \
  algorithm.adv_estimator=gae \
  data.train_files="$TRAIN_FILE" \
  data.val_files="$VAL_FILE" \
  data.train_batch_size=8 \
  data.val_batch_size=8 \
  data.max_prompt_length=512 \
  data.max_response_length=256 \
  data.prompt_key=prompt \
  data.reward_fn_key=data_source \
  data.filter_overlong_prompts=True \
  actor_rollout_ref.model.path="$MODEL_PATH" \
  actor_rollout_ref.model.use_remove_padding=False \
  actor_rollout_ref.actor.optim.lr=1e-6 \
  actor_rollout_ref.actor.ppo_mini_batch_size=8 \
  actor_rollout_ref.actor.ppo_micro_batch_size_per_gpu=1 \
  actor_rollout_ref.rollout.name=vllm \
  actor_rollout_ref.rollout.tensor_model_parallel_size="$ROLLOUT_TP" \
  actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=1 \
  actor_rollout_ref.rollout.gpu_memory_utilization=0.35 \
  actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=1 \
  +actor_rollout_ref.rollout.engine_kwargs.vllm.compilation_config.cudagraph_mode="$VLLM_CUDAGRAPH_MODE" \
  critic.model.path="$MODEL_PATH" \
  critic.model.use_remove_padding=False \
  critic.optim.lr=1e-5 \
  critic.ppo_micro_batch_size_per_gpu=1 \
  algorithm.kl_ctrl.kl_coef=0.001 \
  custom_reward_function.path="$PROJECT_ROOT/rewards/random_binary_reward.py" \
  custom_reward_function.name=compute_score \
  trainer.default_hdfs_dir=null \
  trainer.logger="['console']" \
  trainer.project_name="$PROJECT_NAME" \
  trainer.experiment_name="$EXPERIMENT_NAME" \
  trainer.nnodes=1 \
  trainer.n_gpus_per_node="$N_GPUS" \
  trainer.save_freq=10 \
  trainer.test_freq=10 \
  trainer.total_epochs=1 \
  trainer.critic_warmup=0 \
  trainer.val_before_train=False \
  "${EXTRA_ARGS[@]}"
