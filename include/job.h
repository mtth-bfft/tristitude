#pragma once
#include <Windows.h>

BOOL getProcessJob(HANDLE hProcess, HANDLE *phJob);
void printJobLimits(HANDLE hJob);