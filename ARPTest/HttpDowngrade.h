#pragma once
#include "PacketHandler.h"


class HttpDowngrade : public PacketHandler
{
public:
	void OnTargetForward(std::unique_ptr<BYTE[]>& data, UINT& len);
};
