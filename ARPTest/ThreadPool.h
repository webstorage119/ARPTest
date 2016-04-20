#pragma once
#include <queue>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <thread>
#include <vector>
#include <atomic>


class ThreadPool
{
protected:
	std::queue<std::function<void()> > m_tasks;
	std::mutex m_tasksLock;
	std::condition_variable m_cond;
	std::vector<std::thread> m_threads;
	std::atomic_bool m_stop;

	void Thread();

public:
	ThreadPool(int nThreads);
	~ThreadPool();

	void AddTask(std::function<void()>&& task);
	void StopThreads();
};

extern ThreadPool g_threadPool;
