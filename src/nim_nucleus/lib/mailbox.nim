import std/asyncdispatch
import std/options
import ./asyncsync

type
  MailboxObj[T] = object
    queue: AsyncQueue[T]
    fut: Future[T]
  Mailbox*[T] = ref MailboxObj[T]

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc `=destroy`[T](x: MailboxObj[T]) =
  try:
    if not x.fut.isNil:
      if x.fut.finished:
        discard x.fut.read()
      else:
        let err = new IOError
        x.fut.fail(err)
  except:
    discard

# ------------------------------------------------------------------------------
# Constructor:
# ------------------------------------------------------------------------------
proc newMailbox*[T](queuelen: int): Mailbox[T] =
  new result
  result.queue = newAsyncQueue[T](queuelen)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc full*[T](self: Mailbox[T]): bool {.inline.} =
  result = self.queue.full()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc empty*[T](self: Mailbox[T]): bool {.inline.} =
  result = self.queue.empty()

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc send*[T](self: Mailbox[T], data: T) {.async.} =
  await self.queue.put(data)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc put*[T](self: Mailbox[T], data: T) {.async.} =
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
proc putNoWait*[T](self: Mailbox[T], data: T): bool =
  result = self.sendNoWait(data)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc receive*[T](self: Mailbox[T], timeout: int = 0): Future[Option[T]] {.async.} =
  if self.fut.isNil:
    self.fut = self.queue.get()
  var res: T
  if timeout > 0:
    let received = await withTimeout(self.fut, timeout.int)
    if not received:
      return
    else:
      res = self.fut.read()
  else:
    res = await self.fut
  self.fut = nil
  result = some(res)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc get*[T](self: Mailbox[T], timeout: int = 0): Future[Option[T]] {.async.} =
  result = await self.receive(timeout)
