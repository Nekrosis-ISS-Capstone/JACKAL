#pragma once
#ifndef ANTIANALYSIS_H
#define ANTIANALYSIS_H

#include "API/headers/api.h"


class AntiAnalysis
{
	bool CheckPebForDebug(API::APIResolver& resolver);

public:
	bool IsBeingWatched(API::APIResolver& resolver);
	bool DelayExecution(float fMins, API::APIResolver& resolver);
	int  Nuke(API::APIResolver& resolver);

};
#endif // !ANTIANALYSIS_H