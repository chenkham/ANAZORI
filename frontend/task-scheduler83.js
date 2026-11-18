// Let input and painting run between independent pieces of setup work.
export function yieldToBrowser() {
  if (typeof globalThis.scheduler?.yield === 'function') return globalThis.scheduler.yield();
  return new Promise(resolve => setTimeout(resolve, 0));
}

export function createTaskQueue() {
  let tail = Promise.resolve();
  return work => {
    const result = tail.then(async () => { await yieldToBrowser(); return work(); });
    // A failed asset must not prevent later scenes from loading.
    tail = result.catch(() => {});
    return result;
  };
}
