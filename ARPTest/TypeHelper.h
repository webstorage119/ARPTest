#pragma once
#include <map>
#include <memory>
#include <mutex>


struct MacAddress
{
	BYTE byteArray[6];
	
	MacAddress()
	{
		memset(byteArray, 0, sizeof(byteArray));
	}

	MacAddress& operator = (const MacAddress& other)
	{
		memcpy(byteArray, other.byteArray, sizeof(byteArray));
		return *this;
	}

	operator CString () const
	{
		CString ret;
		ret.Format("%02X-%02X-%02X-%02X-%02X-%02X", byteArray[0], byteArray[1], byteArray[2], byteArray[3], byteArray[4], byteArray[5]);
		return ret;
	}

	bool operator == (const MacAddress& other) const
	{
		return memcmp(byteArray, other.byteArray, sizeof(byteArray)) == 0;
	}

	bool operator < (const MacAddress& other) const
	{
		return memcmp(byteArray, other.byteArray, sizeof(byteArray)) < 0;
	}
};

struct HostInfoSetting
{
	// information
	DWORD ip;
	MacAddress mac;
	DWORD send, receive, replace;

	// image infomation
	struct HttpImageLink
	{
		WORD sourcePort;
		std::unique_ptr<BYTE[]> initPacket;
		DWORD initPacketLen;
	};
	std::map<WORD, HttpImageLink> httpImageLink; // port -> HttpImageLink
	std::mutex httpImageLinkLock;

	// setting
	BOOL cheatTarget, cheatGateway;
	BOOL forward;
	BOOL replaceImages;
	CString imagePath;
	DWORD imageDataLen;
	std::unique_ptr<BYTE[]> imageData;
	std::mutex imageDataLock;

	HostInfoSetting()
	{
		ip = 0;
		cheatTarget = cheatGateway = TRUE;
		forward = TRUE;
		send = receive = replace = 0;
		replaceImages = FALSE;
		imageDataLen = 0;
	}

	~HostInfoSetting()
	{
		if (imageData != nullptr)
		{
			imageDataLock.lock();
			imageData.reset();
			imageDataLock.unlock();
		}
	}
};
