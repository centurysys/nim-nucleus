import std/asyncdispatch
import std/options
import results
import ./asyncsync
import ./errcode
export results
export errcode

type
  MailboxObj[T] = object
    queue: AsyncQueue[T]
    fut: Future[T]
    closed: bool
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
proc send*[T](self: Mailbox[T], data: T): Future[Result[bool, ErrorCode]] {.async.} =
  if self.closed:
    if not self.fut.isNil:
      let err = new IOError
      self.fut.fail(err)
    return err(ErrorCode.Disconnected)
  await self.queue.put(data)
  result = ok(true)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc put*[T](self: Mailbox[T], data: T): Future[Result[bool, ErrorCode]] {.async.} =
  if self.closed:
    if not self.fut.isNil:
      let err = new IOError
      self.fut.fail(err)
    return err(ErrorCode.Disconnected)
  await self.queue.put(data)
  result = ok(true)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc sendNoWait*[T](self: Mailbox[T], data: T): Result[bool, ErrorCode] =
  if self.closed:
    if not self.fut.isNil:
      let err = new IOError
      self.fut.fail(err)
    return err(ErrorCode.Disconnected)
  if not self.queue.full:
    self.queue.putNoWait(data)
    result = ok(true)
  else:
    result = err(ErrorCode.Full)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc putNoWait*[T](self: Mailbox[T], data: T): Result[bool, ErrorCode] =
  result = self.sendNoWait(data)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc close*[T](self: Mailbox[T]) =
  self.closed = true
  if not self.fut.isNil:
    let err = new IOError
    self.fut.fail(err)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc receive*[T](self: Mailbox[T], timeout: int = 0): Future[Result[T, ErrorCode]]
    {.async.} =
  if self.closed:
    result = err(ErrorCode.Disconnected)
  if self.fut.isNil:
    self.fut = self.queue.get()
  var res: T
  if timeout > 0:
    let received = await withTimeout(self.fut, timeout.int)
    if not received:
      return err(ErrorCode.Timeouted)
    else:
      res = self.fut.read()
  else:
    res = await self.fut
  self.fut = nil
  result = ok(res)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc get*[T](self: Mailbox[T], timeout: int = 0): Future[Result[T, ErrorCode]] {.async.} =
  result = await self.receive(timeout)

# ------------------------------------------------------------------------------
#
# ------------------------------------------------------------------------------
proc contains*[T](self: Mailbox[T]): bool =
  if not self.fut.isNil:
    result = self.fut.finished
