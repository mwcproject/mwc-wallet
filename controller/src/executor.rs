// Copyright 2026 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::Error;
use mwc_wallet_util::RwLock;
use mwc_wallet_util::mwc_crates::futures::Future;
use mwc_wallet_util::mwc_crates::futures::task::{ArcWake, Context, Poll, waker_ref};
use mwc_wallet_util::mwc_crates::log::error;
use mwc_wallet_util::mwc_crates::serde_json;
use mwc_wallet_util::mwc_crates::tokio::runtime::{Handle, RuntimeFlavor};
use mwc_wallet_util::mwc_crates::tokio::task;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

// Custom executor example. It is not much related to this implementation because
// rust future model was changed a lot.
// https://rust-lang.github.io/async-book/02_execution/04_executor.html

type WorkerResult = Result<serde_json::Value, Error>;
type WorkerThread = thread::JoinHandle<WorkerResult>;

pub struct RunHandlerInThread {
	// running flag is modifiable from worker thread and Poll.
	running: Arc<AtomicBool>,
	waker: Arc<RwLock<Option<std::task::Waker>>>,
	// Need option because join require ownership transfer. That is why can't belong to 'self' dicertly
	// (State, Result<Response<Body>>)  - resulting from API call as required by gotham
	worker_thread: RwLock<Option<WorkerThread>>,
}

struct ThreadCompletion {
	running: Arc<AtomicBool>,
	waker: Arc<RwLock<Option<std::task::Waker>>>,
}

impl Drop for ThreadCompletion {
	fn drop(&mut self) {
		// This guard is created before handler construction, so completion is
		// published on both a normal return and panic unwinding.
		self.running.store(false, Ordering::Release);
		if let Some(waker) = self.waker.write().take() {
			waker.wake();
		}
	}
}

// We don't want to wake up. Our runner will be pretty dammy, but it is good enough for Rest API.
struct FakeWaker {}

impl ArcWake for FakeWaker {
	fn wake_by_ref(_arc_self: &Arc<Self>) {
		// No wake needed
	}
}

/// Join a worker while allowing Tokio to replace the runtime thread which is
/// performing a cancellation drop. RPC futures can themselves depend on the
/// global Tokio runtime, so directly blocking one of its workers can deadlock
/// shutdown when enough requests are cancelled together.
fn join_cancelled_worker(worker: WorkerThread) {
	let use_blocking_region = !worker.is_finished()
		&& Handle::try_current()
			.is_ok_and(|handle| handle.runtime_flavor() == RuntimeFlavor::MultiThread);
	let result = if use_blocking_region {
		task::block_in_place(move || worker.join())
	} else {
		worker.join()
	};
	match result {
		Ok(Ok(_)) => {}
		Ok(Err(err)) => {
			// The request was cancelled, so logging the worker error is sufficient;
			// there is no caller left to propagate it to.
			error!("RunHandlerInThread worker failed during cancellation: {}", err);
		}
		Err(_) => {
			error!("RunHandlerInThread worker panicked during cancellation");
		}
	}
}

impl RunHandlerInThread {
	pub fn new<F>(handler: F) -> Result<RunHandlerInThread, Error>
	where
		F: Send
			+ Sync
			+ 'static
			+ FnOnce() -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value, Error>>>>,
	{
		// 'self' variables
		let running = Arc::new(AtomicBool::new(true));
		let waker: Arc<RwLock<Option<std::task::Waker>>> = Arc::new(RwLock::new(None));

		// thread variables to move
		let thr_waker = waker.clone();
		let thr_running = running.clone();

		let worker_thread = thread::Builder::new()
			.name("RunHandlerInThread".to_string())
			.spawn(move || {
				let _completion = ThreadCompletion {
					running: thr_running,
					waker: thr_waker,
				};
				let mut future = handler();

				let fw = Arc::new(FakeWaker {});
				let waker = waker_ref(&fw);
				let mut context = &mut Context::from_waker(&*waker);

				let result: Result<serde_json::Value, Error>;

				loop {
					match future.as_mut().poll(&mut context) {
						Poll::Pending => {
							thread::sleep(Duration::from_millis(200));
							continue;
						}
						Poll::Ready(res) => {
							result = res;
							break;
						}
					}
				}
				result
			})
			.map_err(|e| {
				Error::GenericError(format!(
					"Failed to start a RunHandlerInThread thread, {}",
					e
				))
			})?;

		Ok(Self {
			running,
			waker,
			worker_thread: RwLock::new(Some(worker_thread)),
		})
	}
}

impl Drop for RunHandlerInThread {
	fn drop(&mut self) {
		// A JoinHandle detaches its thread when dropped. Hyper cancels an
		// overlong request by dropping this future, so synchronously consume the
		// handle here and keep context cleanup from outliving the wallet RPC.
		if let Some(worker) = self.worker_thread.get_mut().take() {
			join_cancelled_worker(worker);
		}
	}
}

impl Future for RunHandlerInThread {
	type Output = Result<serde_json::Value, Error>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		{
			// Only the task from the most recent poll may be notified when the
			// worker completes. The task can change when a future is moved between
			// executors or otherwise polled with a different context.
			let mut registered_waker = self.waker.write();
			if !registered_waker
				.as_ref()
				.is_some_and(|waker| waker.will_wake(cx.waker()))
			{
				*registered_waker = Some(cx.waker().clone());
			}
		}

		if self.running.load(Ordering::Acquire) {
			// We are still running.
			Poll::Pending
		} else {
			// The job is done. From the thread we should be able to reprieve the results.
			// Because of all ownership staff we can process this once only.
			// Result Must be OK with Ready or Error.
			// In this case futures executor guarantee call it once and satisfy get tread data once limitation

			// JoinHandle::join required ownership transfer. That is why it can be done once.
			if let Some(thr_info) = self.worker_thread.write().take() {
				// Gettign results from the task
				let result = match thr_info.join() {
					Ok(r) => r,
					Err(_) => Err(Error::GenericError(
						"RunHandlerInThread thread is dead".into(),
					)),
				};
				Poll::Ready(result)
			} else {
				Poll::Ready(Err(Error::GenericError(
					"Background thread for REST API was already processed".into(),
				)))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::mpsc;

	fn await_with_timeout(runner: RunHandlerInThread) -> Result<serde_json::Value, Error> {
		let (sender, receiver) = mpsc::channel();
		thread::spawn(move || {
			let result = mwc_wallet_util::mwc_crates::futures::executor::block_on(runner);
			let _ = sender.send(result);
		});

		receiver
			.recv_timeout(Duration::from_secs(2))
			.expect("RunHandlerInThread did not publish worker completion")
	}

	#[test]
	fn handler_construction_panic_is_returned_as_error() {
		let runner = RunHandlerInThread::new(
			|| -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value, Error>>>> {
				panic!("handler construction panic")
			},
		)
		.unwrap();

		assert!(matches!(
			await_with_timeout(runner),
			Err(Error::GenericError(message))
				if message == "RunHandlerInThread thread is dead"
		));
	}

	#[test]
	fn future_poll_panic_is_returned_as_error() {
		struct PanicOnPoll;

		impl std::future::Future for PanicOnPoll {
			type Output = Result<serde_json::Value, Error>;

			fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
				panic!("future poll panic");
			}
		}

		let runner = RunHandlerInThread::new(
			|| -> Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value, Error>>>> {
				Box::pin(PanicOnPoll)
			},
		)
		.unwrap();

		assert!(matches!(
			await_with_timeout(runner),
			Err(Error::GenericError(message))
				if message == "RunHandlerInThread thread is dead"
		));
	}

	#[test]
	fn poll_notifies_the_most_recent_waker() {
		struct RecordingWaker {
			woken: Arc<AtomicBool>,
		}

		impl ArcWake for RecordingWaker {
			fn wake_by_ref(arc_self: &Arc<Self>) {
				arc_self.woken.store(true, Ordering::Release);
			}
		}

		let release_worker = Arc::new(AtomicBool::new(false));
		let thr_release_worker = release_worker.clone();
		let mut runner = RunHandlerInThread::new(move || {
			Box::pin(async move {
				while !thr_release_worker.load(Ordering::Acquire) {
					thread::sleep(Duration::from_millis(1));
				}
				Ok(serde_json::json!(null))
			})
		})
		.unwrap();

		let first_woken = Arc::new(AtomicBool::new(false));
		let first_waker_state = Arc::new(RecordingWaker {
			woken: first_woken.clone(),
		});
		let first_waker = waker_ref(&first_waker_state);
		let mut first_context = Context::from_waker(&*first_waker);
		let first_poll = Pin::new(&mut runner).poll(&mut first_context);

		let second_woken = Arc::new(AtomicBool::new(false));
		let second_waker_state = Arc::new(RecordingWaker {
			woken: second_woken.clone(),
		});
		let second_waker = waker_ref(&second_waker_state);
		let mut second_context = Context::from_waker(&*second_waker);
		let second_poll = Pin::new(&mut runner).poll(&mut second_context);

		release_worker.store(true, Ordering::Release);
		let wake_deadline = std::time::Instant::now() + Duration::from_secs(2);
		while !first_woken.load(Ordering::Acquire)
			&& !second_woken.load(Ordering::Acquire)
			&& std::time::Instant::now() < wake_deadline
		{
			thread::sleep(Duration::from_millis(1));
		}
		let completion = Pin::new(&mut runner).poll(&mut second_context);

		assert!(matches!(first_poll, Poll::Pending));
		assert!(matches!(second_poll, Poll::Pending));
		assert!(!first_woken.load(Ordering::Acquire));
		assert!(second_woken.load(Ordering::Acquire));
		assert!(matches!(completion, Poll::Ready(Ok(_))));
	}

	#[test]
	fn cancellation_drop_waits_for_worker_completion() {
		let worker_started = Arc::new(AtomicBool::new(false));
		let release_worker = Arc::new(AtomicBool::new(false));
		let worker_finished = Arc::new(AtomicBool::new(false));
		let thr_worker_started = worker_started.clone();
		let thr_release_worker = release_worker.clone();
		let thr_worker_finished = worker_finished.clone();

		let runner = RunHandlerInThread::new(move || {
			Box::pin(async move {
				thr_worker_started.store(true, Ordering::Release);
				while !thr_release_worker.load(Ordering::Acquire) {
					thread::sleep(Duration::from_millis(1));
				}
				thr_worker_finished.store(true, Ordering::Release);
				Ok(serde_json::json!(null))
			})
		})
		.unwrap();

		let start_deadline = std::time::Instant::now() + Duration::from_secs(2);
		while !worker_started.load(Ordering::Acquire) && std::time::Instant::now() < start_deadline
		{
			thread::sleep(Duration::from_millis(1));
		}
		if !worker_started.load(Ordering::Acquire) {
			release_worker.store(true, Ordering::Release);
			drop(runner);
			panic!("request worker did not start");
		}

		// Drop from a Tokio worker, matching cancellation of a Hyper connection task.
		let runtime = mwc_wallet_util::mwc_crates::tokio::runtime::Builder::new_multi_thread()
			.worker_threads(1)
			.enable_all()
			.build()
			.unwrap();
		let (drop_started_sender, drop_started_receiver) = mpsc::channel();
		let (drop_finished_sender, drop_finished_receiver) = mpsc::channel();
		let drop_task = runtime.spawn(async move {
			drop_started_sender.send(()).unwrap();
			drop(runner);
			drop_finished_sender.send(()).unwrap();
		});

		if drop_started_receiver
			.recv_timeout(Duration::from_secs(2))
			.is_err()
		{
			release_worker.store(true, Ordering::Release);
			runtime.block_on(drop_task).unwrap();
			panic!("cancellation task did not start");
		}
		let dropped_before_release =
			drop_finished_receiver.recv_timeout(Duration::from_millis(100));
		let worker_finished_before_release = worker_finished.load(Ordering::Acquire);

		release_worker.store(true, Ordering::Release);
		if matches!(dropped_before_release, Err(mpsc::RecvTimeoutError::Timeout)) {
			drop_finished_receiver
				.recv_timeout(Duration::from_secs(2))
				.expect("cancellation drop did not join the released worker");
		}
		runtime.block_on(drop_task).unwrap();
		assert!(matches!(
			dropped_before_release,
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		assert!(!worker_finished_before_release);
		assert!(worker_finished.load(Ordering::Acquire));
	}
}
