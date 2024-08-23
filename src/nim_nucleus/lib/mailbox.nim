import std/asyncdispatch
import std/options
import ./asyncsync

type
  MailboxObj[T] = object of RootObj
    queue: AsyncQueue[T]
  Mailbox*[T] = ref MailboxObj[T]

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newMailbox*[T](queuelen: int): Mailbox[T] =
  new result
  result.queue = newAsyncQueue[T](queuelen)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc send*[T](self: Mailbox[T], data: T) {.async.} =
  await self.queue.put(data)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sendNoWait*[T](self: Mailbox[T], data: T): bool =
  if not self.queue.full:
    self.queue.putNoWait(data)
    result = true

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc receive*[T](self: Mailbox[T], timeout: uint = 0): Future[Option[T]] {.async.} =
  let fut = self.queue.get()
  var res: T
  if timeout > 0:
    let received = await withTimeout(fut, timeout.int)
    if not received:
      let dummy = new T
      await self.queue.put(dummy[])
      discard await fut
      return
    else:
      res = fut.read()
  else:
    res = await fut
  result = some(res)
