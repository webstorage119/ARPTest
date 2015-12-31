#pragma once


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
