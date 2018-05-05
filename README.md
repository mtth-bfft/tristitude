# tristitude

A simple process security policy enumerator. Currently tested settings mainly include (per-process, per-executable or system-wide) job properties and mitigation policies. This tool is a work in progress based on Google's great [sandbox-attacksurface-analysis-tools](https://github.com/google/sandbox-attacksurface-analysis-tools).

## Usage

To display information about an already running process, use `.\tristitude.exe /p <pid>`. Otherwise, if you can run arbitrary commands inside a sandbox you want to test, run the binary without arguments from within.
