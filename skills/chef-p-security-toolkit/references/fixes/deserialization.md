# Unsafe deserialization
Signals: `pickle.load(s)`, `marshal`, `yaml.load` without SafeLoader, `torch.load` default, Java `ObjectInputStream`, .NET `BinaryFormatter`, PHP `unserialize`, Node `node-serialize`.
Fix: use a data-only format (JSON, MessagePack, protobuf). Python: `yaml.safe_load`; `json`. ML: save weights as safetensors; `torch.load(path, weights_only=True)`; treat `.pkl/.joblib/.pt` from outside your control as code execution. Scan downloaded model files with picklescan.
If the data must stay pickle: only load files you created yourself, from a location untrusted users cannot write, optionally HMAC-signed and verified before loading. That is mitigation, not a fix: say so.
Stop and ask if the on-disk or wire format must change (stored data migration).
Verify: bandit B301/B302/B506, semgrep rule ids; test that malicious/unknown input is rejected.
