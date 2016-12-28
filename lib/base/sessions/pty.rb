# Advanced Post Exploitation
#
#

# require 'staekka_path'
# $LOAD_PATH.push(staekka_path() + '/external/termios/lib/termios')
# $LOAD_PATH.push(ENV['STAEKKA_PATH'] + '/external/termios/lib/termios')
# $LOAD_PATH.push(ENV['STAEKKA_PATH'] + '/external/termios/ext')

require 'pty'
require 'expect'
require 'termios'
#gem 'ruby-termios', require: 'termios'
# require 'ruby-termios'
require 'io/console'

# require ::File.dirname(__FILE__) + '/../../../' + 'external/' + 'termios/lib/termios'
require 'base/sessions/shell_session'
require 'base/sessions/shell_connection'
require 'base/sessions/shell_extensions'
require 'base/sessions/cache'
require 'base/sessions/updatedb'

module Msf
  module Sessions
    #
    # PTY implements an expect like session for interacting with a command
    # (usually a shell) and using STDIN/STDOUT/STDERR as input/output for a
    # metasploit session
    #
    class PTY < ShellSession
      # class PTY < CommandShell
      include Msf::Session::Basic
      include Msf::Session::Provider::SingleCommandShell
      include Msf::Sessions::ShellExtensions
      include Msf::Sessions::SessionCaching
      include Msf::Sessions::Updatedb

      attr_accessor :arch
      attr_accessor :platform
      attr_accessor :verbose
      attr_accessor :staekka

      def initialize(*args)
        super
        # ring.size = 1024 * 4
        ring = nil
      end

      #
      # just a description
      #
      def desc
        "Pty I/O"
      end

      #
      # close the shell
      #
      def shell_close
        rstream.close
      end

      #      def shell_read_until_token_XXX(token, wanted_idx = 0, timeout = 5, absolute_timeout = 30)
      #        if (wanted_idx == 0)
      #          parts_needed = 2
      #        else
      #          parts_needed = 1 + (wanted_idx * 2)
      #        end
      #
      #        # Read until we get the data between two tokens or absolute timeout.
      #        begin
      #          ::Timeout.timeout(timeout) do
      #            buf = ''
      #            idx = nil
      #            loop do
      #              if (tmp = shell_read(-1, 2))
      #                buf << tmp
      #
      #                # see if we have the wanted idx
      #                parts = buf.split(token, -1)
      #                if (parts.length == parts_needed)
      #                  # cause another prompt to appear (just in case)
      #                  shell_write("\n")
      #                  return parts[wanted_idx]
      #                end
      #              end
      #            end
      #          end
      #        rescue
      #          # nothing, just continue
      #        end
      #
      #        # failed to get any data or find the token!
      #        nil
      #
      #      end

      #      class Rex::IO::RingBuffer
      #        def select
      #          #::IO.select(nil, nil, nil, 0.10)
      #          [[], [self.fd], []]
      #        end
      #      end

      #
      # A class for handling the IO of the process
      #
      class PtySocket < ShellConnection
        attr_accessor :stdout
        attr_accessor :stdin
        #                attr_accessor :winsize
        attr_accessor :expect_command
        attr_accessor :tty
        attr_accessor :pid

        #        include ::Rex::IO::Stream
        require 'io/console'

        def initialize(command = nil, stop_string = nil, logfile = nil)
          if command.nil?
            command = ENV["SHELL"] # use default shell
          end

          self.peer_info = "local:"
          self.expect_command = command
          self.stdin = nil
          self.stdout = nil
          self.pid = 999999999

          #                    self.winsize = [nil, nil]
          # $stdout.sync = true
          # $stdin.sync = true

          #                    max_winsize = 65536 - 256
          #                    $stdin.winsize[1] = 40, max_winsize
          #                    $stdout.winsize[1] = 40, max_winsize
          (self.stdout, self.stdin, self.pid) = ::PTY.spawn(expect_command)
          ##############
          # tty
          @tty = Regexp.last_match[1] if stdin.inspect.to_s =~ /(\/dev\/.*)>/

          ###########################

          #                    attr = Termios::getattr( $stdin )
          #                    Termios::setattr( stdin, Termios::TCSANOW, attr )

          stdout.sync = true
          stdin.sync = true
          #                    stdout.sync = false
          #                    stdin.sync = false
          #
          # wait 1 secund
          select(nil, nil, nil, 0.5)
          write("\n")

          super
          # read whatever
          # read(-1) if has_read_data?
        end

        #        def respond_to?(symbol, include_all=false)
        #          if symbol == :ring
        #            return false
        #          end
        #          super
        #        end

        def sync
          length = def_block_size
          timeout = 2
          begin
            ::Timeout.timeout(timeout) do
              # loop do
              5.times do
                begin
                  # self.mutex.synchronize do
                  # if   Rex::ThreadSafe.select([ stdout ], nil, nil, 0.01)
                  # self.mutex.synchronize do
                  data = stdout.read_nonblock(length)
                  # end

                  break if data.nil?
                  store_data(data)
                # else
                # break
                # end
                # end
                rescue ::Errno::EWOULDBLOCK
                  # Rex::ThreadSafe.select([ stdout ], nil, nil, 0.1)
                  # retry
                  break
                rescue ::Errno::EAGAIN
                  break
                end
              end
            end
          rescue
            # puts "__rescue___"
            return nil
          end
          nil
        end

        def default_logfile
          super() + "_pty_pid=#{pid}"
        end

        #
        # stdin as io
        #
        def to_io
          stdin.to_io
        end

        #
        # a description
        #
        def peerinfo
          "PTY: #{@expect_command}"
        end

        #
        # it is a local connection
        #
        def localinfo
          "local"
        end

        #
        # interact with the shell
        #
        def interactive
          return nil if stdin.nil?
          return nil if stdout.nil?
          unless $stdout.tty?
            $stdout.puts "This $stdout is not a tty. Not all tty features are supported."
          end
          set_default_winsize
          stop_string = stop_interactive
          $stdout.print "\nend this shell with \"#{stop_string}\"\n"
          begin
            data_input = ''
            data_output = ''
            @is_interactive = true
            stdin_buffer false
            loop do
              break if stdin.closed?
              if IO.select([$stdin], nil, nil, 0.01)
                data = $stdin.sysread(1)
                stdin.print data
                log_stdin(data)
                data_input << data
              end
              if data_input.end_with?(stop_string)
                $stdout.print "\nStopping interactive\n"
                break
              end
              # if has_read_data?(0.01)
              # $stdout.print ">> has data -> go |#{$ERROR_INFO}|\n"
              next unless IO.select([stdout], nil, nil, 0.01)
              # if Rex::ThreadSafe.select([ stdout ], nil, nil, 0.01)
              length = 8192
              # begin
              data = stdout.read_nonblock(length)
              # rescue
              # end
              next unless data
              $stdout.write data
              $stdout.flush
              # log_stdout(data)
              data_output << data
              # end
            end
            $stdout.puts "__interactive__break"
            stdin_buffer true
          rescue
            $stdout.puts "__interactive__rescue"
          ensure
            @is_interactive = false
            stdin_buffer true
          end

          @is_interactive = false
          stdin_buffer true
          # remove stop_string from STDIN
          remove = "\r" * stop_string.length
          stdin.print remove
          stdin.print "\n"
          data_output
        end

        # XXXXXXXXX
        # TODO
        def interactive_rxvt
          raise "Not implemented yet"
          # command = "urxvt -pty-fd #{@tty}"
        end

        #                def echo (enable)
        #                    return unless defined?( Termios )
        #                    attr = Termios::getattr( $stdin )
        #                    if enable
        #                        attr.c_lflag |= Termios::ICANON | Termios::ECHO
        #                    else
        #                        attr.c_lflag &= ~(Termios::TCSANOW|Termios::ECHO)
        #                    end
        #                    Termios::setattr( $stdin, Termios::TCSANOW, attr )
        #                end
        #

        #
        # Flush buffer for @stdin and @stdout
        #
        # def flush_X
        #  super
        #  stdout.flush
        #  stdin.flush
        # end

        def readline
          stdout.readline
        end

        #
        # read data from STDIN
        #
        #        def read_stout_X(length = -1, _opts = {})
        #          #$stdout.puts "__________read: #{caller}"
        #          data = nil
        #          if (length.nil?) or  (length < 0)
        #            length =  65536
        #            #                                                length =  16384
        #          end
        #          begin
        #            ###########################
        #            # stdin_buffer false
        #            stdin_sync false
        #            # length = 4096  # TODO: good option?
        #            # length =  65536 #
        #            #########################
        #            Rex::ThreadSafe.select([ stdout ], nil, nil, 1)
        #            data = stdout.read_nonblock(length)
        #            log_stdout(data)
        #            # stdin_buffer true
        #            stdin_sync true
        #            #$stdout.puts "--------------------READ\n>>#{data.dump}<<"
        #            return data
        #          rescue ::Errno::EWOULDBLOCK
        #            print_debug "[WAIT]  ::Errno::EWOULDBLOCK #{$ERROR_INFO}"
        #            Rex::ThreadSafe.select([ stdout ], nil, nil, 0.5)
        #            retry
        #            #return data
        #          rescue ::Errno::EAGAIN
        #            # Sleep for a half a second, or until we can read again
        #            Rex::ThreadSafe.select([ stdout ], nil, nil, 0.5)
        #            print_debug "[WAIT] Errno::EAGAIN #{$ERROR_INFO}"
        #            # Decrement the block size to handle full sendQs better
        #            retry
        #            #return data
        #          rescue ::IOError, ::Errno::EPIPE
        #            print_debug "::IOError, ::Errno::EPIPE #{$ERROR_INFO}"
        #            # stdin_buffer(true)
        #            stdin_sync true
        #            return nil
        #          end
        #        end

        #
        # write to STDIN
        #
        def write(buf, _opts = {})
          # flush
          # $stdout.puts "--------------------WRITE\n>>#{buf.dump}<<"
          total_sent   = 0
          total_length = buf.length
          #####################
          block_size   = 32768
          # block_size   = 4096

          #                    i=0
          begin
            # stdin_buffer false
            while total_sent < total_length
              #                            wait_before_write
              s = ::IO.select(nil, [ stdin ], nil, 0.1)
              # s = Rex::ThreadSafe.select([ stdin ], nil, nil, 0.1)
              if  s.nil? || s[1].nil?
                if s.nil?
                  Rex::ThreadSafe.select(nil, nil, nil, 0.5)
                  print_debug "write(): wait for ::IO.select(nil, [ stdin ], nil, 0.1)"
                  # puts "_________write wait____________"
                  # Rex::ThreadSafe.select(nil, nil, nil, 1)
                  redo
                end
                next
              end
              data = buf[total_sent, block_size]
              sent = stdin.write_nonblock(data)
              log_stdin(data)
              sync
              total_sent += sent if sent > 0
            end
            # stdin_buffer true
          rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
            # Sleep for a half a second, or until we can write again
            Rex::ThreadSafe.select(nil, [ stdin ], nil, 0.5)
            #                        self.stdin.fsync
            # Decrement the block size to handle full sendQs better
            print_debug "Errno::EAGAIN, ::Errno::EWOULDBLOCK #{$ERROR_INFO}"
            block_size = 1024
            # Try to write the data again
            retry
          rescue ::IOError, ::Errno::EPIPE
            print_debug "IOError, ::Errno::EPIPE #{$ERROR_INFO}"
            # stdin_buffer true
            return nil
          rescue
            print_debug "[ERRoR] #{$ERROR_INFO}"
          end
          total_sent
        end

        #                def wait_before_write
        #                    wait_length = 0.00001
        #                    Rex::ThreadSafe.select( nil, nil, nil, wait_length )
        #                end

        #
        # is there data to read in STDOUT?
        #
        #        def has_read_data_X?(timeout = nil)
        #          $stdout.puts "has_read_data?(#{timeout})"
        #          $stdout.puts caller
        #          # Allow a timeout of "0" that waits almost indefinitely for input, this
        #          # mimics the behavior of Rex::ThreadSafe.select() and fixes some corner
        #          # cases of unintentional no-wait timeouts.
        #          timeout = 3600 if timeout && timeout == 0
        #
        #          begin
        #            if (rv = ::IO.select([ stdout ], nil, nil, timeout)) &&
        #                (rv[0]) &&
        #                (rv[0][0] == stdout)
        #              $stdout.puts "has_read_data?(#{timeout})\t:true"
        #              true
        #            else
        #              $stdout.puts "has_read_data?(#{timeout})\t:false"
        #              false
        #            end
        #          rescue ::Errno::EBADF, ::Errno::ENOTSOCK
        #            raise ::EOFError
        #          rescue StreamClosedError, ::IOError, ::EOFError, ::Errno::EPIPE
        #            #  Return false if the socket is dead
        #            $stdout.puts "has_read_data?(#{timeout})\t:err"
        #            return false
        #          end
        #        end

        #
        # kill the process and close STDIN
        #
        def close
          stdin.close
          ::Process.kill("SIGINT", pid)
        end

        #
        # super() unless it is interactive at the moment
        #
        #      def get_once(length = -1, timeout = 10)
        #        #$stdout.puts caller
        #        #$stdout.puts "___get_once(#{length},#{timeout})____________"
        #
        #        return nil if interactive?
        #        super
        #      end

        def fd
          stdout
        end
      end
    end
  end
end
