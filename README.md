# testing-the-use-of-Sigstore-in-simulated-open-source-supply-chain-security-measures
This repo is a hands-on experiment that compares traditional key-pair security measures to Sigstore incorporated security measures, both at the beginning of the software supply chain, which is an open-source repository such as PyPI, npm, etc. and at the end-user side. 

## How to run

### First run the repo-side experiment by:
1. run kam_service.py
2. in a separate terminal, run test_setup.py to make sure everything is working properly
3. run run_trial.py

### Then run the end-user side experiment by:
1. run quickstart_enduser.py
2. run run_enduser_experiment.py
3. run analyze_enduser_results.py
