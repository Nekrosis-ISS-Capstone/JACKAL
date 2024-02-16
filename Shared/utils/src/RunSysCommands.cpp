#include "utils/headers/RunSysCommands.h"
#include <array>
#include <memory>
#include <stdexcept>
#include <Windows.h>



std::string RunSysCommands::ExecCommand(const char* szCommand)
{
	std::string result;			  // Result after manipulation
	std::array<char, 128> buffer; // Used to read output from command
	std::shared_ptr<FILE> pipe(_popen(szCommand, "r"), _pclose);


	if (!pipe)
	{
		throw std::runtime_error("failed to open pipe");
	}
	while (!feof(pipe.get()))
	{
		if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
			result += buffer.data();
	}

	return result;
}

std::string RunSysCommands::GetProductKey()
{
	std::string output = ExecCommand("wmic path softwarelicensingservice get OA3xOriginalProductKey");

	// Remove the substring "OA3xOriginalProductKey" from the output
	size_t pos = output.find("OA3xOriginalProductKey");
	if (pos != std::string::npos) {
		output.erase(pos, sizeof("OA3xOriginalProductKey"));
	}

	// Remove leading and trailing whitespace again
	output.erase(0, output.find_first_not_of("  \t\n\r\f\v"));
	output.erase(output.find_last_not_of("  \t\n\r\f\v") + 2);

	MessageBoxA(NULL, output.c_str(), NULL, NULL);

	return output;
}
