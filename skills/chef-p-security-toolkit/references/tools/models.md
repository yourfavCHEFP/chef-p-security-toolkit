# Reading model-file scans
picklescan (`picklescan.txt`) lists pickle files with dangerous imports (os, subprocess, builtins eval/exec, socket). Anything flagged: do not load it. Prefer safetensors; `torch.load(..., weights_only=True)`. Unflagged does not mean safe: only load models from sources you trust.
