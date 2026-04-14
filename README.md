# SDFuzz

SDFuzz is a directed fuzzing tool driven by target states. It leverages selective instrumentation and early termination, combined with distance metrics to optimize fuzzing efficiency.

## Installation and Usage

### Option 1: Docker

We provide a Docker image at [`phli25/sdfuzz`](https://hub.docker.com/r/phli25/sdfuzz/tags). Please check out the latest versions.

### Option 2: Build from Source

1. Install the modified SVF from [temporal-specialization](/temporal-specialization/INSTALL.md). Follow steps 2 and 2.1 to install llvm-7.0.0 and SVF.

2. Install the fuzzer and instrumentation pass:
   ```bash
   cd sdfuzz/
   make clean all
   cd instr/
   make clean all
   cd ../llvm_mode
   make clean all
   ```

3. Use the fuzzer like typical AFL/AFLGo tools.

### Example Usage

We provide a use case example at `/scripts/fuzz/libming-CVE-2016-9827.sh`, which takes an input of `libming-CVE-2016-9827.crash`.

## Credits

This implementation is based on [temporal-specialization](https://github.com/shamedgh/temporal-specialization/), [SelectFuzz](https://github.com/cuhk-seclab/selectfuzz), and [SieveFuzz](https://github.com/HexHive/SieveFuzz). We are grateful to their respective authors for making their work open source.

## License 
This project is [Apache License, Version 2.0](LICENSE).

## Citation

```bibtex
@inproceedings{sec24:sdfuzz,
    title        = {SDFuzz: Target States Driven Directed Fuzzing},
    author       = {Penghui Li and Wei Meng and Chao Zhang},
    year         = 2024,
    month        = aug,
    booktitle    = {Proceedings of the 33rd USENIX Security Symposium (Security)}
}
```
