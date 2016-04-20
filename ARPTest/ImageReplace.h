#pragma once
#include "PacketHandler.h"
#include <memory>
#include "SyncMap.h"
#include <mutex>
#include "TypeHelper.h"


class ImageReplace : public PacketHandler
{
public:
	bool OnTargetPacket(const pcap_pkthdr* header, const BYTE* pkt_data);
	bool OnGatewayPacket(const pcap_pkthdr* header, const BYTE* pkt_data);

	struct Config
	{
		UINT replace = 0;

		bool replaceImages = false;
		CString imagePath;
		DWORD imageDataLen = 0;
		std::unique_ptr<BYTE[]> imageData;
		std::mutex imageDataLock;

		// image infomation used to send image
		struct SendImageInfo
		{
			WORD sourcePort;
			std::unique_ptr<BYTE[]> initPacket;
			DWORD initPacketLen;
		};
		SyncMap<WORD, SendImageInfo> sendImageInfo; // port -> SendImageInfo
	};
	Config& GetConfig(IpAddress ip);
	void SetConfig(IpAddress ip, bool replaceImages, const CString& imagePath);

protected:
	SyncMap<IpAddress, Config> m_attackList; // IP -> Config

	void SendImageThread(IpAddress targetIp, WORD targetPort);
};
