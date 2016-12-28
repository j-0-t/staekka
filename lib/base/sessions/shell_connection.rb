# Advanced Post Exploitation

require 'termios'

module Msf
  module Sessions
    #
    # Shell provides some functions for interactive shells with tty support
    #
    class ShellConnection
      attr_accessor :stop_interactive
      attr_accessor :logfile
      attr_accessor :log_in
      attr_accessor :log_out
      attr_accessor :log_dump
      attr_accessor :fd        # The associated socket or IO object for this ring buffer
      attr_accessor :mutex     # The mutex locking access to the queue
      attr_accessor :peer_info
      attr_accessor :pid
      attr_accessor :buffer

      include ::Rex::IO::Stream

      def initialize(_command = nil, stop_string = nil, logfile = nil, _ssh_options = nil, _tty = true)
        stop_string = '#__stop__' if stop_string.nil?
        self.stop_interactive = stop_string
        self.log_in = nil
        self.log_out = nil
        @is_interactive = false

        self.buffer = StringIO.new
        self.mutex = Mutex.new

        ###########################
        # debugging
        #
        if logfile
          logfile = default_logfile if logfile == "default"
          start_logging(logfile) # XXX for testing
          self.logfile = logfile
          # start with a newline
          log_in.print "\n"
        end
      end

      def default_logfile
        directory = '/tmp/'
        filename = 'staekka_log'
        directory + filename
      end

      # opens a terminal with tail -f on the logfile which shows pty IO in
      # "live"
      def start_tailf
        unless ENV['DISPLAY'].nil?
          cmd = "xterm -e 'tail -f #{self.logfile}'"
          Kernel.spawn cmd
        end
      end

      #
      # it is running interactive at the moment?
      #
      def interactive?
        @is_interactive
      end

      # setting the terminal buffer (Termios::)
      #
      def stdin_buffer(enable)
        # Fix for armitage
        return unless $stdout.tty?

        return unless defined?(Termios)
        attr = Termios.getattr($stdin)
        if enable
          attr.c_lflag |= Termios::ICANON | Termios::ECHO
        else
          attr.c_lflag &= ~(Termios::ICANON | Termios::ECHO)
        end
        Termios.setattr($stdin, Termios::TCSANOW, attr)
      end

      #
      # start the logging into a file
      #
      def start_logging(file)
        log = ::File.open(file, "a")
        dump_log = ::File.open("#{file}.dump", "a")
        self.logfile = file
        self.log_in = log
        self.log_out = log
        self.log_dump = dump_log
        log_in.sync = true
        log_out.sync = true
        log_dump.sync = true
      end

      #
      # log all data from STDIN
      #
      def log_stdin(data)
        if data && log_in
          log_in.print data
          log_dump.print("STDIN=#{data.dump}\n")
        end
      end

      #
      # log all data from STDOUT
      #
      def log_stdout(data)
        if data && log_out
          log_out.print data
          log_dump.print("STDOUT=#{data.dump}\n")
        end
      end

      ############################
      # reset to default winsize for zsh shell
      # using xterm command "resize"
      # (most users are using some X, so in most cases it is fine
      # TODO: better alternative|non-X users?
      def set_default_winsize
        # return unless self.expect_command.match("zsh")
        write("\neval `resize`\n")
        #                 shell_command "eval `resize`"
        #                 tmp = rstream.winsize
        #                 unless tmp[0].nil? or tmp[1].nil?
        #                     cmd = "stty rows #{tmp[0]}; stty columns #{tmp[1]}"
        #                     puts "STTY: #{cmd}"
        #                     shell_command(cmd)
        #                 end
      end

      def print_debug(string)
        $stdout.puts(string)
      end

      def stdin_sync(enable)
        if enable
          $stdin.sync = true
          $stdout.sync = true
        else
          $stdin.sync = false
          $stdout.sync = true
        end
      end


      def def_block_size
        65536
        # 4096
      end

      def store_data(data)
        return if data.nil?
        mutex.synchronize do
          t = buffer.pos
          buffer.pos = buffer.length
          buffer << data
          buffer.pos = t
        end
      end

      def read_data(length)
        data = nil
        mutex.synchronize do
          begin
            data = buffer.read_nonblock(length)
          rescue
          end
        end
        data
      end

      def has_read_data?(_timeout = nil)
        sync
        buffer.pos < buffer.length
      end

      def read(length = -1, _opts = {})
        length = def_block_size if length.nil? || (length < 0)
        data = nil
        begin
          # sync
          data = read_data(length)
          log_stdout(data)
          return data
        rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
          # Sleep for a half a second, or until we can read again
          Rex::ThreadSafe.sleep 0.5
          sync
          print_debug "[WAIT] Errno::EAGAIN, ::Errno::EWOULDBLOCK #{$ERROR_INFO}"
          # Decrement the block size to handle full sendQs better
          retry
        rescue ::IOError, ::Errno::EPIPE
          sync
          retry
          print_debug "::IOError, ::Errno::EPIPE #{$ERROR_INFO}"
          # stdin_buffer(true)
          return data
        end
        nil
      end

      def get_once(_length = -1, _timeout = 10)
        return nil if interactive?
        sync
      end

      def read_buffered(length = -1, timeout = 10)
        return nil if interactive?
        sync
        return nil if has_read_data?(timeout) == false
        bsize = length == -1 ? def_block_size : length
        data  = read(bsize)

        data
      end

      def flush
        mutex.synchronize do
          buffer.reopen('')
        end
      end

    end
  end
end
