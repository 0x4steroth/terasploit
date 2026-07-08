"""
Terasploit Framework (c) 2026

Author:          4steroth
License:         BSD-3-Clause
Path:            teralibs/terasploit/framework/thread/handler.py
"""

import queue
import threading
import traceback
import uuid

from teralibs.terasploit.framework.thread.output_bus import OutputBus


STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_KILLED = "killed"

_TERMINAL = frozenset({STATUS_COMPLETED, STATUS_FAILED, STATUS_KILLED})


class ModuleContext:
    """
    Execution context passed as the first argument to every module run().
    """

    def __init__(
        self,
        job_id,
        bus,
        kill_event,
    ):
        self.job_id = job_id
        self.bus = bus
        self.kill_event = kill_event

    def is_killed(self):
        """Return True when this job has been asked to stop."""
        return self.kill_event.is_set()

    def info(self, message):
        """Emit an informational log message."""
        self.bus.emit(self.job_id, "info", message)

    def success(self, message):
        """Emit a success log message."""
        self.bus.emit(self.job_id, "success", message)

    def warning(self, message):
        """Emit a warning log message."""
        self.bus.emit(self.job_id, "warning", message)

    def error(self, message):
        """Emit an error log message."""
        self.bus.emit(self.job_id, "error", message)


class ThreadHandler:
    """
    Manages a pool of daemon worker threads and a shared job queue.
    """

    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.output_bus = OutputBus()

        # Thread-safe queue holding incoming tasks for worker threads
        self._task_queue = queue.Queue()

        # Global shutdown signal used to stop worker threads gracefully
        self._shutdown = threading.Event()

        # Registry of active tasks keyed by task ID with metadata/state tracking
        self._tasks = {}

        # Per-task cancellation signals allowing individual task termination
        self._kill_events = {}

        # Per-task completion signals used to notify when a task finishes execution
        self._done_events = {}

        # Registered driver instances mapped by name or identifier
        self._drivers = {}

        # Lock used to synchronize access to shared state across threads
        self._lock = threading.Lock()

        # List of active worker thread objects managed by the scheduler
        self._workers = []

        self._start_workers()

    # Worker lifecycle

    def _start_workers(self):
        """Spawn max_threads daemon worker threads."""
        for index in range(self.max_threads):
            t = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name=f"tsf-worker-{index + 1}",
            )
            t.start()
            self._workers.append(t)

    def _worker_loop(self):
        """Main loop executed by each worker thread."""
        while not self._shutdown.is_set():
            try:
                task_id, func, args, kwargs = self._task_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if task_id is None:
                self._task_queue.task_done()
                return

            with self._lock:
                if self._tasks[task_id]["status"] == STATUS_KILLED:
                    self._task_queue.task_done()
                    self._done_events[task_id].set()
                    continue
                self._tasks[task_id]["status"] = STATUS_RUNNING

            kill_event = self._kill_events[task_id]
            ctx = ModuleContext(task_id, self.output_bus, kill_event)

            try:
                result = func(ctx, *args, **kwargs)

                with self._lock:
                    if kill_event.is_set():
                        self._tasks[task_id]["status"] = STATUS_KILLED
                    else:
                        self._tasks[task_id]["status"] = STATUS_COMPLETED
                        self._tasks[task_id]["result"] = result

            except Exception as exc:  # pylint: disable=broad-except
                ctx.error(str(exc))
                with self._lock:
                    if kill_event.is_set():
                        self._tasks[task_id]["status"] = STATUS_KILLED
                    else:
                        self._tasks[task_id]["status"] = STATUS_FAILED
                        self._tasks[task_id]["error"] = str(exc)
                        self._tasks[task_id]["traceback"] = traceback.format_exc()

            finally:
                self._task_queue.task_done()
                self._done_events[task_id].set()

    # Public interface

    def submit(
        self,
        func,
        *args,
        **kwargs,
    ):
        """
        Enqueue *func* for execution and return the task UUID string.
        """
        task_id = str(uuid.uuid4())
        kill_event = threading.Event()
        done_event = threading.Event()

        with self._lock:
            self._tasks[task_id] = {
                "status": STATUS_QUEUED,
                "result": None,
                "error": None,
                "traceback": None,
            }
            self._kill_events[task_id] = kill_event
            self._done_events[task_id] = done_event

        self._task_queue.put((task_id, func, args, kwargs))
        return task_id

    def status(self, task_id):
        """
        Return a snapshot of the task record, or None if not found.


        Returns
        -------
        dict or None
        """
        with self._lock:
            entry = self._tasks.get(task_id)
            return dict(entry) if entry else None

    def all_tasks(self):
        """Return a snapshot of all task records."""
        with self._lock:
            return {tid: dict(info) for tid, info in self._tasks.items()}

    def active_tasks(self):
        """Return a snapshot of tasks that are queued or running."""
        with self._lock:
            return {
                tid: dict(info)
                for tid, info in self._tasks.items()
                if info["status"] not in _TERMINAL
            }

    def active_count(self):
        """Return the number of tasks currently queued or running."""
        with self._lock:
            return sum(1 for info in self._tasks.values() if info["status"] not in _TERMINAL)

    def kill_task(self, task_id):
        """
        Gracefully stop a queued or running job.

        Parameters
        ----------
        task_id : str
            Full or 8-character prefix UUID of the job to kill.

        Returns
        -------
        bool
            True if the kill was issued; False otherwise.
        """
        full_id = self._resolve_id(task_id)
        if full_id is None:
            return False

        with self._lock:
            rec = self._tasks.get(full_id)
            if rec is None or rec["status"] in _TERMINAL:
                return False
            self._kill_events[full_id].set()
            if rec["status"] == STATUS_QUEUED:
                rec["status"] = STATUS_KILLED
                self._done_events[full_id].set()

        with self._lock:
            driver = self._drivers.get(full_id)
        if driver is not None:
            try:
                driver.stop()
            except Exception:  # pylint: disable=broad-except
                pass

        return True

    def clear_completed(self):
        """
        Remove all terminal jobs from the records.

        Returns
        -------
        int
            Number of records removed.
        """
        with self._lock:
            to_remove = [tid for tid, info in self._tasks.items() if info["status"] in _TERMINAL]
            for tid in to_remove:
                del self._tasks[tid]
                self._kill_events.pop(tid, None)
                self._done_events.pop(tid, None)
                self._drivers.pop(tid, None)

        return len(to_remove)

    def register_driver(self, task_id, driver):
        """
        Associate an ExploitDriver with a task.

        """
        with self._lock:
            self._drivers[task_id] = driver

    def unregister_driver(self, task_id):
        """
        Remove the driver association for *task_id*.

        """
        with self._lock:
            self._drivers.pop(task_id, None)

    def wait_until_done(self, task_id, poll=0.05):
        """
        Block until *task_id* leaves the running state.

        Parameters
        ----------
        poll : float
            Seconds to wait per call before returning.

        Returns
        -------
        bool
            True when done; False when the poll timeout expired.
        """
        full_id = self._resolve_id(task_id)
        if full_id is None:
            return True

        with self._lock:
            done_event = self._done_events.get(full_id)
        if done_event is None:
            return True

        return done_event.wait(timeout=poll)

    def _resolve_id(self, partial):
        """
        Match a full or 8-char prefix task ID against known tasks.


        Returns
        -------
        str or None
        """
        if not partial:
            return None
        with self._lock:
            if partial in self._tasks:
                return partial
            matches = [tid for tid in self._tasks if tid.startswith(partial)]
            return matches[0] if len(matches) == 1 else None

    def shutdown(self, timeout=5.0):
        """
        Signal all workers to stop and wait for them to finish.

        """
        self._shutdown.set()
        for worker in self._workers:
            worker.join(timeout=timeout)

    def set_max_threads(self, new_max):
        """
        Resize the worker pool to *new_max* threads.

        """
        new_max = max(1, int(new_max))
        current = len(self._workers)

        if new_max > current:
            for index in range(current, new_max):
                t = threading.Thread(
                    target=self._worker_loop,
                    daemon=True,
                    name=f"tsf-worker-{index + 1}",
                )
                t.start()
                self._workers.append(t)

        elif new_max < current:
            excess_workers = self._workers[new_max:]
            # Signal each excess worker to exit via sentinel task.
            for _ in range(current - new_max):
                self._task_queue.put((None, None, (), {}))
            # Shrink the active list immediately; excess threads will drain
            # their sentinel and exit on their own.
            self._workers = self._workers[:new_max]
            # Join excess threads in the background so shutdown() doesn't need
            # to worry about them and they don't outlive their intent.
            reaper = threading.Thread(
                target=lambda: [t.join(timeout=5.0) for t in excess_workers],
                daemon=True,
                name="tsf-worker-reaper",
            )
            reaper.start()

        self.max_threads = new_max
