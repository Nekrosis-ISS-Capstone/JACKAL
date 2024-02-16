#ifndef RUNSYSCOMMANDS_H
#define RUNSYSCOMMANDS_H

#pragma once
#include <string>

class RunSysCommands
{
public:
	// Executes a system command silently using pipe
	std::string ExecCommand(const char* szCommand);
	std::string GetProductKey();
};


#endif // !RUNSYSCOMMANDS_H


