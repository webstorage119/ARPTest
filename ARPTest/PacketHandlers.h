#pragma once
#include "MITM.h"
#include "HttpDowngrade.h"
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
	
	HttpDowngrade httpDowngrade;
	//ImageReceive imageReceive; // BUG
	ImageReplace imageReplace;

	void Init()
	{
		g_mitm.AddPacketHandler(&httpDowngrade);
		//g_mitm.AddPacketHandler(&imageReceive); // BUG
		g_mitm.AddPacketHandler(&imageReplace);
	}
};

extern PacketHandlers& g_packetHandlers;
