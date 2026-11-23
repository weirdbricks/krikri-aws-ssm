require "lib_c"

lib LibC
  # `openpty` lives in libc on glibc (>= 2.34) and musl, which is what CI uses.
  # On macOS it lives in libutil, so an unconditional binding fails to link;
  # the fake agent's pty is a Linux-only test facility.
  {% unless flag?(:darwin) %}
    fun openpty(amaster : LibC::Int*, aslave : LibC::Int*, name : LibC::Char*,
                termp : Void*, winp : Void*) : LibC::Int
  {% end %}
end

module KrikriAwsSsm::Testing
  # A real pty pair for the fake agent, so the shell exercises canonical-mode
  # line rules (echo, CR/LF, MAX_CANON) instead of a plain pipe.
  class Pty
    getter master : IO::FileDescriptor
    getter slave : IO::FileDescriptor

    def initialize
      # Assigned unconditionally so the ivar-initialization analysis is happy;
      # the macOS branch below raises before either is read.
      @master = uninitialized IO::FileDescriptor
      @slave = uninitialized IO::FileDescriptor
      {% if flag?(:darwin) %}
        raise NotImplementedError.new(
          "the fake agent's pty needs libutil's openpty, which this build does not bind")
      {% else %}
        master_fd = uninitialized LibC::Int
        slave_fd = uninitialized LibC::Int
        result = LibC.openpty(pointerof(master_fd), pointerof(slave_fd),
          Pointer(LibC::Char).null, Pointer(Void).null, Pointer(Void).null)
        raise IO::Error.from_errno("openpty") unless result == 0
        @master = IO::FileDescriptor.new(master_fd)
        @slave = IO::FileDescriptor.new(slave_fd)
        # Crystal sets CLOEXEC on the fds it opens, but an openpty fd arrives bare:
        # the spawned shell used to inherit the MASTER, so closing the pair from the
        # test never hung the shell up - it waited on its own pty forever, survived
        # the shard, and held every fd the shard had (the host compile lock included).
        @master.close_on_exec = true
        @slave.close_on_exec = true
      {% end %}
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
