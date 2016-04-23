#pragma once
#include "PacketHandler.h"
#include "SyncMap.h"
#include <set>
#include <atomic>
#include <mutex>
#include "TypeHelper.h"


class ImageReceive : public PacketHandler
{
public:
	bool OnGatewayPacket(const pcap_pkthdr* header, const BYTE* pkt_data);

	struct Config
	{
		// image infomation used to receive image
		struct ReceiveImageInfo
		{
			std::atomic_int ref;
			bool shouldRelease = false;
			DWORD startSeq = 1;
			std::set<UINT> visitedPos;
			int restContentLen = 0;
			CFile imageFile;
			std::mutex fileLock;

			ReceiveImageInfo()
			{
				ref = 0;
			}
		};
		SyncMap<WORD, ReceiveImageInfo> receiveImageInfo; // port -> ReceiveImageInfo
	};
	Config& GetConfig(IpAddress ip);

protected:
	SyncMap<IpAddress, Config> m_attackList; // IP -> Config

	// start a thread to write image data to file
	void ReceiveImage(IpAddress targetIp, WORD targetPort, const pcap_pkthdr* header, const BYTE* pkt_data, bool isInit);
};
