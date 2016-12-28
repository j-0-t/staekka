# Advanced Post Exploitation
#
#

require 'stringio'
require 'net/ssh'

require 'base/sessions/shell_session'
require 'base/sessions/shell_connection'
require 'base/sessions/shell_extensions'
require 'base/sessions/cache'
require 'base/sessions/updatedb'

module Msf
  module Sessions
    #
    # Interactive SSH shell session (with tty support)
    #
    class SshSession < ShellSession
      include Msf::Session::Basic
      include Msf::Session::Provider::SingleCommandShell
      include Msf::Sessions::ShellExtensions
      include Msf::Sessions::SessionCaching
      include Msf::Sessions::Updatedb

      attr_accessor :arch
      attr_accessor :platform
      attr_accessor :verbose
      attr_accessor :staekka
      attr_accessor :mutex

      def initialize(*args)
        self.verbose = false
        self.staekka = true
        self.platform = "unix" # XXX: todo
        super
        ring.size = 1024 * 4
      end

      # just a description
      #
      def desc
        "SSH Session"
      end

      #
      # waits a little bit and reads command from stdin
      #
      #      def before_enter_X(token = nil)
      #        wait_length = 0.1
      #        Rex::ThreadSafe.select(nil, nil, nil, wait_length)
      #        rstream.flush
      #        if token.nil?
      #          return nil
      #        end
      #
      #        absolute_timeout = 5
      #        buf = ''
      #        begin
      #          ::Timeout.timeout(absolute_timeout) do
      #            rstream.flush
      #            loop do
      #              if (tmp = shell_read(-1, 1))
      #                buf << do_encoding_terminal(tmp)
      #                # buf << do_encoding_terminal2(tmp)
      #                if buf.match(token)
      #                  break
      #                end
      #              else
      #                # sleep 1
      #                Rex::ThreadSafe.select(nil, nil, nil, 0.1)
      #              end
      #            end
      #          end
      #        rescue
      #        end
      #        buf
      #      end

      #
      # execute a command and echo a token when command is finished
      # timeout => a relative timeout (no new output for n seconds -> timeout)
      # absolute_timeout => command can take maximal n seconds
      #
      #      def shell_command_token_unix_X(cmd, timeout = 10, absolute_timeout = 30)
      #        set_shell_token_index(timeout)
      #        token = ::Rex::Text.rand_text_alpha(5)
      #
      #        # Send the command to the session's stdin. + \n to enter it
      #        command = "#{cmd};echo #{token}"
      #
      #        sleep_len = command.length * 0.0001
      #        timeout += sleep_len.to_i
      #        absolute_timeout += sleep_len.to_i
      #
      #        # cause another prompt to appear (just in case)
      #        #                shell_write("\n")
      #        shell_write(command)
      #        before_enter(token)
      #        enter_command
      #        out = shell_read_until_token(token, @shell_token_index, timeout, absolute_timeout)
      #
      #        # cause another prompt to appear (just in case)
      #        # second try
      #        if out.nil?
      #          enter_command
      #          out = shell_read_until_token(token, @shell_token_index, timeout, absolute_timeout)
      #        end
      #        #
      #        #                shell_write("\n")
      #        return nil if out.nil?
      #
      #        # out = do_encoding(out)
      #        out.gsub!("\r\n", "\n")
      ##        t = ::File.new("/tmp/cmd_log2", "a")
      ##        t.puts "#{cmd}:"
      ##        t.print out.dump
      ##        t.close
      #        # remove console colors
      #        # out = remove_colors(out)
      #        out
      #      end

      #      def shell_read_X(length=-1, timeout=1)
      #
      #        begin
      #          rv = rstream.get_once(length, timeout)
      #          framework.events.on_session_output(self, rv) if rv
      #          return rv
      #        rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
      #          #print_error("Socket error: #{e.class}: #{e}")
      #          shell_close
      #          raise e
      #        end
      #      end

      #      class Rex::IO::RingBuffer
      #        def select
      #          #::IO.select(nil, nil, nil, 0.10)
      #          [[], [self.fd], []]
      #        end
      #      end

      class SecureShell < ShellConnection
        attr_accessor :stdout
        attr_accessor :ssh
        attr_accessor :channel
        attr_accessor :ssh_options
        #
        #
        #        def respond_to?(symbol, include_all=false)
        #          if symbol == :ring
        #            return false
        #          end
        #          super
        #        end

        def initialize(command = nil, stop_string = nil, logfile = nil, ssh_options = nil, tty = true)
          # def initialize(ssh_options = nil, command = nil, stop_string = nil, logfile = nil, tty = true)

          # self.mutex = Mutex.new
          self.peer_info = ssh_options[:host_name]
          self.ssh_options = ssh_options
          self.stdout = StringIO.new
          ###########################
          self.ssh =  Net::SSH.start(nil, nil, ssh_options)
          self.channel = ssh.open_channel do |_ch|
            channel.request_pty if tty == true
            if command
              channel.exec command
            else
              channel.send_channel_request "shell"
            end
          end
          channel.on_data do |_c, data|
            store_data(data)
          end
          channel.on_extended_data do |_c, _type, data|
            store_data(data)
          end

          ###########################
          super
          ###########################
          # read whatever
          set_default_winsize
          get_once(-1)
        end

        def default_logfile
          ssh_string = ssh_options[:user] + "@" + ssh_options[:host_name] + ":" + ssh_options[:port].to_s
          super() + "_ssh_#{ssh_string}_#{rand(1000)}"
        end

        #        def store_data_X(data)
        #          self.mutex.synchronize do
        #            t = self.stdout.pos
        #            self.stdout.pos = self.stdout.length
        #            self.stdout << data
        #            self.stdout.pos = t
        #          end
        #        end
        #
        #        def read_data_X(length)
        #          self.mutex.synchronize do
        #              self.stdout.read_nonblock(length)
        #          end
        #        end

        def fd
          stdout
        end

        def sync
          max = 10
          max.times do
            ssh.process 0.01
            ssh.process 0.01
            break if channel.output.content.empty?
          end
          true
        end

        #
        # it is running interactive at the moment?
        #
        def interactive?
          @is_interactive
        end

        def interactive
          unless $stdout.tty?
            $stdout.puts "This $stdout is not a tty. Not all tty features are supported."
          end
          # stdin_buffer false
          set_default_winsize
          stop_string = stop_interactive
          $stdout.print "\nend this shell with \"#{stop_string}\"\n"
          begin
            data_input = ''
            data_output = ''
            @is_interactive = true
            stdin_buffer false
            loop do
              if IO.select([$stdin], nil, nil, 0.001)
                # data = $stdin.sysread(1)
                data = $stdin.sysread(16)
                channel.output.content << data
                # write data
                log_stdin(data)
                data_input << data
              end
              if data_input.end_with?(stop_string)
                $stdout.print "\nStopping interactive\n"
                break
              end
              # begin
              next unless has_read_data?
              data = buffer.read_nonblock(4096)
              # rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
              #  $stdout.puts "____interactive_ERR"
              # rescue ::Errno::EWOULDBLOCK
              # end
              $stdout.write data
            end
            $stdout.puts "__interactive__break"
            stdin_buffer true
          rescue
            $stdout.puts "__interactive__rescue"

          ensure
            @is_interactive = false
            stdin_buffer true
          end

          $stdout.puts "__interactive__end"
          @is_interactive = false
          stdin_buffer true
          # remove stop_string from STDIN
          remove = "\r" * stop_string.length
          write remove
          write "\n"
          data_output
        end

        #
        #        def read_X(length = -1, _opts = {})
        #          #$stdout.puts "__Read(#{self.stdout.pos})____(#{self.stdout.length})"
        #          if (length.nil?) or (length < 0)
        #            length =  65536
        #          end
        #          data =nil
        #          begin
        #            sync
        #            data =  read_data(length)
        #            log_stdout(data)
        #
        #            return data
        #          rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
        #            # Sleep for a half a second, or until we can read again
        #            #Rex::ThreadSafe.select(nil, nil, nil, 0.5)
        #            Rex::ThreadSafe.sleep 0.5
        #            sync
        #            print_debug "[WAIT] Errno::EAGAIN, ::Errno::EWOULDBLOCK #{$ERROR_INFO}"
        #            # Decrement the block size to handle full sendQs better
        #            retry
        #          rescue ::IOError, ::Errno::EPIPE
        #            sync
        #            retry
        #            print_debug "::IOError, ::Errno::EPIPE #{$ERROR_INFO}"
        #            # stdin_buffer(true)
        #            return data
        #          end
        #          nil
        #        end
        #

        def write(buf, _opts = {})
          total_sent   = 0
          total_length = buf.length
          #####################
          block_size   = 32768
          # block_size   = 4096

          #                    i=0
          begin
            # stdin_buffer false
            while  total_sent < total_length
              data = buf[total_sent, block_size]
              channel.output.write data
              log_stdin(data)
              sync
              total_sent += data.length
            end
            # stdin_buffer true
          rescue ::Errno::EAGAIN, ::Errno::EWOULDBLOCK
            # Sleep for a half a second, or until we can write again
            Rex::ThreadSafe.select(nil, nil, nil, 0.5)
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
            #puts "[ERRoR] #{$ERROR_INFO}"
          end
          total_sent
        end

        def readline
          #$stdout.puts "---------readline()"
          sync
          fd.readline
        end

        #        def flush_X
        #          self.mutex.synchronize do
        #            self.stdout.reopen('')
        #          end
        #        end
        #
        #        def has_read_data_X?(timeout = nil)
        #          # Allow a timeout of "0" that waits almost indefinitely for input, this
        #          # mimics the behavior of Rex::ThreadSafe.select() and fixes some corner
        #          # cases of unintentional no-wait timeouts.
        #          timeout = 3600 if timeout && timeout == 0
        #
        #          sync
        #          if self.stdout.pos == self.stdout.length
        #            false
        #          else
        #            true
        #          end
        #
        #        end
      end
    end
  end
end
