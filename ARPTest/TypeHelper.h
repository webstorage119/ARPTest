#pragma once
#include <map>
#include <memory>
#include <mutex>


union IpAddress
{
	BYTE byteArray[4];
	DWORD dwIp;

	IpAddress()
	{
		dwIp = 0;
	}

	IpAddress(DWORD dw)
	{
		dwIp = dw;
	}

	IpAddress& operator = (const char* str)
	{
		DWORD ip[4];
		if (sscanf_s(str, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]) != 4)
			return *this;
		byteArray[0] = (BYTE)ip[0];
		byteArray[1] = (BYTE)ip[1];
		byteArray[2] = (BYTE)ip[2];
		byteArray[3] = (BYTE)ip[3];
		return *this;
	}

	IpAddress& operator = (DWORD dw)
	{
		dwIp = dw;
		return *this;
	}

	operator CString () const
	{
		CString ret;
		ret.Format("%u.%u.%u.%u", byteArray[0], byteArray[1], byteArray[2], byteArray[3]);
		return ret;
	}

	operator const DWORD& () const
	{
		return dwIp;
	}

	operator DWORD& ()
	{
		return dwIp;
	}
};

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
