#pragma once
#include "MITM.h"
#include "ImageReceive.h"
#include "ImageReplace.h"

class PacketHandlers
{
private:
	PacketHandlers() = default;

public:
	static PacketHandlers& GetInstance()
	{
		static PacketHandlers instance;
		return instance;
	}
	
	ImageReceive imageReceive;
	ImageReplace imageReplace;

	void Init()
	{
		g_mitm.AddPacketHandler(&imageReceive);
		g_mitm.AddPacketHandler(&imageReplace);
	}
};

extern PacketHandlers& g_packetHandlers;
