#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H


#pragma once
#include "API/headers/api.h"
#include "utils/headers/Tools.h"


class AntiAnalysis
{
	bool Peb(API::APIResolver& resolver);

public:
	bool PebCheck(API::APIResolver& resolver);
	int Nuke(void);

};
#endif // !ANTIANALYSIS_H