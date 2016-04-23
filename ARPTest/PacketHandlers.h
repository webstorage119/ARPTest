#pragma once
#include "HttpNoEncoding.h"
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
	
	HttpNoEncoding httpNoEncoding;
	ImageReceive imageReceive;
	ImageReplace imageReplace;
};

extern PacketHandlers& g_packetHandlers;
