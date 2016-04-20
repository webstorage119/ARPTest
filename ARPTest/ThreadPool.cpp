#include "stdafx.h"
#include "ThreadPool.h"


ThreadPool g_threadPool(100);


void ThreadPool::Thread()
{
	while (true)
	{
		std::unique_lock<std::mutex> lock(m_tasksLock);
		if (m_stop)
			break;
		if (m_tasks.empty())
			m_cond.wait(lock);
		if (m_stop)
			break;
		if (m_tasks.empty())
			continue;
		std::function<void()> task(std::move(m_tasks.front()));
		m_tasks.pop();
		lock.unlock();

		task();
	}
}

ThreadPool::ThreadPool(int nThreads)
{
	m_stop = false;
	for (int i = 0; i < nThreads; i++)
		m_threads.emplace_back(std::thread(&ThreadPool::Thread, this));
}

ThreadPool::~ThreadPool()
{
	StopThreads();
}

void ThreadPool::AddTask(std::function<void()>&& task)
{
	std::lock_guard<std::mutex> lock(m_tasksLock);
	if (m_tasks.size() > 1)
		TRACE("%u tasks is waiting\n", m_tasks.size());
	m_tasks.emplace(task);
	m_cond.notify_one();
}

void ThreadPool::StopThreads()
{
	if (!m_stop)
	{
		{
		std::lock_guard<std::mutex> lock(m_tasksLock);
		m_stop = true;
		m_cond.notify_all();
		}
		for (auto& thread : m_threads)
			thread.join(); // tasks must return!
		m_threads.clear();

		TRACE("threads end\n");
	}
}
