require "lib_c"

lib LibC
  # `openpty` lives in libc on glibc (>= 2.34) and musl, which is what CI uses.
  fun openpty(amaster : LibC::Int*, aslave : LibC::Int*, name : LibC::Char*,
              termp : Void*, winp : Void*) : LibC::Int
end

module KrikriAwsSsm::Testing
  # A real pty pair for the fake agent, so the shell exercises canonical-mode
  # line rules (echo, CR/LF, MAX_CANON) instead of a plain pipe.
  class Pty
    getter master : IO::FileDescriptor
    getter slave : IO::FileDescriptor

    def initialize
      master_fd = uninitialized LibC::Int
      slave_fd = uninitialized LibC::Int
      result = LibC.openpty(pointerof(master_fd), pointerof(slave_fd),
        Pointer(LibC::Char).null, Pointer(Void).null, Pointer(Void).null)
      raise IO::Error.from_errno("openpty") unless result == 0
      @master = IO::FileDescriptor.new(master_fd)
      @slave = IO::FileDescriptor.new(slave_fd)
    end

    def close_slave : Nil
      @slave.close unless @slave.closed?
    end

    def close : Nil
      close_slave
      @master.close unless @master.closed?
    end
  end
end
