#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H


#pragma once
#include "API/headers/api.h"


class AntiAnalysis
{
	bool Peb(API::APIResolver& resolver);

public:
	bool PebCheck(API::APIResolver& resolver);
	int  Nuke(API::APIResolver& resolver);

};
#endif // !ANTIANALYSIS_H