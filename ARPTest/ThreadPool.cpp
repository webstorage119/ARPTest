#include "stdafx.h"
#include "ThreadPool.h"


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
		std::unique_ptr<Task> task(std::move(m_tasks.front()));
		m_tasks.pop();
		lock.unlock();

		task->Run();
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

void ThreadPool::AddTask(std::unique_ptr<Task> task)
{
	{
	std::lock_guard<std::mutex> lock(m_tasksLock);
	m_tasks.emplace(std::move(task));
	}
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
			thread.join();
		m_threads.clear();
	}
}
