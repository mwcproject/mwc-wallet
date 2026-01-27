use crate::error::Error;
use futures::task::{waker_ref, ArcWake, Context, Poll};
use futures::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

// Custom executor example. It is not much related to this implementation because
// rust future model was changed a lot.
// https://rust-lang.github.io/async-book/02_execution/04_executor.html

pub struct RunHandlerInThread {
	// running flag is modifiable from worker thread and Poll.
	running: Arc<AtomicBool>,
	waker: Arc<RwLock<Option<std::task::Waker>>>,
	// Need option because join require ownership transfer. That is why can't belong to 'self' dicertly
	// (State, Result<Response<Body>>)  - resulting from API call as required by gotham
	worker_thread: RwLock<Option<thread::JoinHandle<Result<serde_json::Value, Error>>>>,
}

// We don't want to wake up. Our runner will be pretty dammy, but it is good enough for Rest API.
struct FakeWaker {}

impl ArcWake for FakeWaker {
	fn wake_by_ref(_arc_self: &Arc<Self>) {
		// No wake needed
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

				thr_running.store(false, Ordering::Relaxed);

				if let Some(waker) = thr_waker.write().unwrap_or_else(|e| e.into_inner()).take() {
					waker.wake();
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

impl Future for RunHandlerInThread {
	type Output = Result<serde_json::Value, Error>;

	fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		if self
			.waker
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.is_none()
		{
			// Update current task. at the first polling.
			// Task is needed by thread to notify future executor that job is done
			self.waker
				.write()
				.unwrap_or_else(|e| e.into_inner())
				.replace(cx.waker().clone());
		}

		if self.running.load(Ordering::Relaxed) {
			// We are still running.
			Poll::Pending
		} else {
			// The job is done. From the thread we should be able to reprieve the results.
			// Because of all ownership staff we can process this once only.
			// Result Must be OK with Ready or Error.
			// In this case futures executor guarantee call it once and satisfy get tread data once limitation

			// JoinHandle::join required ownership transfer. That is why it can be done once.
			if let Some(thr_info) = self
				.worker_thread
				.write()
				.unwrap_or_else(|e| e.into_inner())
				.take()
			{
				// Gettign results from the task
				let result = match thr_info.join() {
					Ok(r) => r,
					Err(_) => Err(Error::GenericError(
						"RunHandlerInThread thread is dead".into(),
					)),
				};
				Poll::Ready(result)
			} else {
				// Likely double processing. See comments above.
				panic!("Background thread for REST API died or double processed!");
			}
		}
	}
}
