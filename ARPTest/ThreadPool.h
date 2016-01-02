#pragma once

#include <queue>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <atomic>


class Task
{
public:
	virtual ~Task() {}
	virtual void Run() = 0;
};

class ThreadPool
{
protected:
	std::queue<std::unique_ptr<Task> > m_tasks;
	std::mutex m_tasksLock;
	std::condition_variable m_cond;
	std::vector<std::thread> m_threads;
	std::atomic_bool m_stop;

	void Thread();

public:
	ThreadPool(int nThreads);
	~ThreadPool();

	void AddTask(std::unique_ptr<Task> task);
	void StopThreads();
};
