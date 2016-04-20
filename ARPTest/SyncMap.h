#pragma once
#include <map>
#include <mutex>


template<class _Kty, class _Ty>
class SyncMap : public std::map<_Kty, _Ty>
{
private:
	typedef std::map<_Kty, _Ty> super;

public:
	std::recursive_mutex m_lock;
	typedef std::lock_guard<decltype(m_lock)> lock_guard;

	mapped_type& operator[](const key_type& _Keyval)
	{
		lock_guard lock(m_lock);
		return super::operator[](_Keyval);
	}

	iterator find(const key_type& _Keyval)
	{
		lock_guard lock(m_lock);
		return super::find(_Keyval);
	}

	size_type erase(const key_type& _Keyval)
	{
		lock_guard lock(m_lock);
		return super::erase(_Keyval);
	}
};
