# Advanced Post Exploitation

module Msf
  module Sessions
    #
    # Basic commands for interactive shell sessions
    #
    class ShellSession < CommandShell
      attr_accessor :orig_suspend_c
      attr_accessor :orig_suspend_d

      def initialize(*args)
        self.verbose = false
        self.staekka = true
        self.platform = "unix" # XXX: todo

        super
      end

      # Override for server implementations that can't do ssl
      def supports_ssl?
        false
      end

      def supports_zlib?
        false
      end

      #
      # creating a new shell session
      # * setting a new session environment
      # * fixing some issues with some shells/prompts
      # TODO: oh-my-zsh does not work at the moment
      #
      def new_session
        # disable autocorrect (oh-my-zsh)
        shell_write("unsetopt correct_all; unsetopt correct\n")
        # fixing oh-my-zsh themes
        shell_write("PROMPT='$ '\n")
        # fixing issues with ZSH syntax highlighting (not very common)
        shell_write("unset ZSH_HIGHLIGHT_HIGHLIGHTERS\n")
        # fixing issues with exotic ZSH prompts
        shell_write("prompt  off\n")
        ###

        # disable bash completetion
        shell_write("complete -r\n")
        # enter
        shell_write("\n")
        # second enter
        shell_write("\n")
        #############
        # new_session_start
        rstream.flush
      end

      #
      # execute a command and echo a token
      #
      def shell_command_token(cmd, timeout = 10, absolute_timeout = 30)
        output = if platform =~ /win/
                   shell_command_token_win32(cmd, timeout)
                 else
                   shell_command_token_unix(cmd, timeout, absolute_timeout)
                 end
        output
      end

      #
      # finding out where the output of commands will be
      # NOTE: if the session echoes input we don't need to echo the token twice.
      # This setting will persist for the duration of the session.
      #
      def set_shell_token_index(_timeout = 1, reset = false)
        # @shell_token_index = 0
        unless reset == true
          return @shell_token_index if @shell_token_index
        end

        token = ::Rex::Text.rand_text_alpha(32)
        numeric_token = rand(0xffffffff) + 1
        cmd = "echo #{numeric_token}"

        # cause another prompt to appear (just in case)
        shell_write("\n")
        # ... and wait a second
        Rex::ThreadSafe.select(nil, nil, nil, 1)

        shell_write(cmd + ";echo #{token}")
        before_enter(token)
        enter_command
        buf = before_enter(token)
        parts = buf.split(token, -1)
        i = 0
        parts.length.times do
          tmp = parts[i]
          # some shells/prompt (zsh) are adding some \a to the output.
          #
          if tmp.match "\a"
            tmp = tmp.split("\a", -1)[2]
          end
          if tmp.to_i == numeric_token
            @shell_token_index = i
            return
          end
          i = + 1
        end

        # raise "Cannot identify the token" + "\n[DEBUG] token=\"#{token}\" command ouput=\"#{buf}\""
        @shell_token_index = 1 # default
      end

      #
      # execute a command and echo a token when command is finished
      # timeout => a relative timeout (no new output for n seconds -> timeout)
      # absolute_timeout => command can take maximal n seconds
      #
      def shell_command_token_unix(cmd, timeout = 10, absolute_timeout = 30)
        set_shell_token_index(timeout)
        token = ::Rex::Text.rand_text_alpha(5)

        # Send the command to the session's stdin. + \n to enter it
        cmd.strip!
        # avoid syntax errors like
        #     bash: syntax error near unexpected token `;'
        command = if cmd.end_with? '&'
                    "#{cmd}; sleep 1; echo #{token}"
                  else
                    "#{cmd};echo #{token}"
                  end

        sleep_len = command.length * 0.0001
        timeout += sleep_len.to_i
        absolute_timeout += sleep_len.to_i

        # cause another prompt to appear (just in case)
        shell_write(command)
        before_enter(token)
        enter_command
        out = shell_read_until_token(token, @shell_token_index, timeout, absolute_timeout)

        # cause another prompt to appear (just in case)
        # second try
        if out.nil?
          enter_command
          out = shell_read_until_token(token, @shell_token_index, timeout, absolute_timeout)
        end
        #
        return nil if out.nil?

        first_line = out.to_s.index("\n")
        if first_line.nil?
          first_line = 0
        else
          first_line += 1
        end
        out[0, first_line] = ''
        # out = do_encoding(out)
        out.gsub!("\r\n", "\n")
        # remove console colors
        # out = remove_colors(out)
        out
      end

      #
      # Read from the command shell.
      #
      def shell_read(length = -1, timeout = 1)
        rv = rstream.read_buffered(length, timeout)
        framework.events.on_session_output(self, rv) if rv
        return rv
      rescue ::Rex::SocketError, ::EOFError, ::IOError, ::Errno::EPIPE => e
        # print_error("Socket error: #{e.class}: #{e}")
        shell_close
        raise e
      end

      #
      # reads from STDIN until a token is found
      # token => the token to look for
      # wanted_idx => which output (between 2 tokens?)
      # timeout => a relative timeout (no new output for n seconds -> timeout)
      # absolute_timeout => command can take maximal n seconds
      #
      def shell_read_until_token(token, wanted_idx = 0, timeout = 5, absolute_timeout = 30)
        timeout = 5 if timeout.nil?
        if timeout > absolute_timeout
          absolute_timeout = timeout + absolute_timeout
        end

        parts_needed = if wanted_idx.zero?
                         2
                       else
                         1 + (wanted_idx * 2)
                       end
        buf = ''
        timeout_count = timeout
        # Read until we get the data between two tokens or absolute timeout.
        begin
          ::Timeout.timeout(absolute_timeout) do
            loop do
              if timeout_count <= 0
                #                                puts "TIMEOUT=0"
                vprint_debug("got timeout during reading from shell")
                vprint_debug("last data: #{buf.dump}")
                break
              end

              if (tmp = shell_read(-1, 1)) # BUG

                if tmp.empty?
                  vprint_debug("shell_read() is empty: timeoutcount=#{timeout_count}|#{$ERROR_INFO}") # XXX for testing
                  timeout_count -= 1
                  # sleep 0.5
                  Rex::ThreadSafe.select(nil, nil, nil, 0.5)
                  next
                end

                timeout_count = timeout
                # buf << do_encoding_terminal(tmp)
                buf << tmp
                #########################
                if wanted_idx.zero?
                  break if buf.match(token)
                else
                  parts = buf.split(token, -1)
                  break if parts.length == parts_needed
                end

              else
                timeout_count -= 0.1
                # sleep 1
                Rex::ThreadSafe.select(nil, nil, nil, 0.1)
              end
            end

            return nil if buf.empty?
            parts = buf.split(token, -1)
            if parts.length == parts_needed
              output = parts[wanted_idx].to_s
              # "Token found"
            else
              # "Token NOT found"
              ################
              # try to recover
              if parts.length > 1
                # i = 0
                vprint_debug("...recovering output...")
                parts.length.times do |i|
                  if parts[i].to_s.end_with?("echo ")
                    vprint_debug("...found...")
                    output = parts[i + 1]
                  end
                end
              end
            end
            return nil if output.nil?
            return output
          end
        rescue
          vprint_debug("shell_read_until_token(): read timeout #{$ERROR_INFO}") # XXX for testing
          return buf
          # nothing, just continue
        end
        # failed to get any data or find the token!
        nil.to_s
      end

      #
      # waits a little bit and reads command from stdin
      #
      def before_enter(token = nil)
        wait_length = 0.1
        Rex::ThreadSafe.select(nil, nil, nil, wait_length)
        if token.nil?
          rstream.flush
          return nil
        end

        absolute_timeout = 5
        buf = ''
        begin
          ::Timeout.timeout(absolute_timeout) do
            rstream.sync
            loop do
              if (tmp = shell_read(-1, 1))
                buf << do_encoding_terminal(tmp)
                break if buf.match(token)
              else
                # sleep 1
                Rex::ThreadSafe.select(nil, nil, nil, 0.1)
              end
            end
          end
        rescue
        end
        rstream.flush
        buf
      end

      #
      # waits a little bit and writes \n
      #
      def enter_command
        shell_write("\n")
        wait_length = 0.1
        Rex::ThreadSafe.select(nil, nil, nil, wait_length)
      end

      #
      # Installs a signal handler to monitor init signal notifications.
      #
      def handle_crtl_c(enable = true)
        $stdout.puts "handle_crtl_c() 1"
        if enable == false
          self.orig_suspend_c = @saved_orig_suspend_c
        else
          if orig_suspend_c.nil?
            $stdout.puts "handle_crtl_c() 1"
            begin
              @saved_orig_suspend_c = orig_suspend_c
              self.orig_suspend_c = Signal.trap("INT") {
                if prompt_yesno("Send [CRTL-C] to shell session? ")
                  $stdout.puts "-> [CRTL-C]"
                  data = 3.chr
                  rstream.write data
                else
                  $stdout.puts ">> [CRTL-C]"

                end
              }
            rescue
            end
          end
        end
      end

      #
      # interactive modus with the shell
      #
      def interactive
        rstream.interactive
      end

      #
      # starting interactive modus
      #
      def interact(user_input, user_output)
        # Detach from any existing console
        detach if interacting
        init_ui(user_input, user_output)
        self.interacting = true
        self.completed = false
        eof = false

        # Start the readline stdin monitor
        # XXX disabled
        # user_input.readline_start() if user_input.supports_readline

        # Handle suspend notifications
        handle_suspend
        handle_crtl_c

        # As long as we're interacting...
        while interacting == true

          begin
            rstream.interactive
            _suspend
            $stdout.puts "interActive(1)"
            eof = true if _interrupt
          end

          break if eof
        end

        begin

          ##########
          rstream.stdin_buffer true
          # Restore the suspend handler
          restore_suspend

          # If we've hit eof, call the interact complete handler
          _interact_complete if eof == true

          # Shutdown the readline thread
          # XXX disabled
          # user_input.readline_stop() if user_input.supports_readline
          handle_crtl_c(false)
          # Detach from the input/output handles
          reset_ui

        ensure

          # Mark this as completed
          self.completed = true
        end

        # Return whether or not EOF was reached
        eof
      end

      #
      # does the shelloutput has colors?
      #
      def has_colors?(data)
        data.match(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/)
      end

      #
      # remove colors from the shell output
      #
      def remove_colors(data)
        data.gsub(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/, "")
      end

      #
      # decode the shell output
      # (removing newline at the beginning)
      # (replacing \r\n with \n
      #
      def do_encoding(string)
        ## removing newline (needed for pty/expect newlines)
        string[0, 2] = '' if string.start_with? "\r\n"
        string[0, 3] = '' if string.start_with? "\r\r\n"
        string.gsub!("\r\n", "\n")
        # string.chomp!
        string
      end

      #
      # remove terminal characters
      #		\r\r	-> \r
      #		\r\n	-> \n
      #		remove colors
      #		...
      #
      def do_encoding_terminal(string)
        string = string.to_s
        string.gsub!("\r\r", "\r")
        string.gsub!("\r\n", "\n")
        string.gsub!("\r\$\s", "")

        string.gsub!(/.\r/, "")
        string.gsub!(/\x1B\[\d*?[ABCDsuKJ]/, '')
        string
      end

      def do_encoding_terminal2(tmp)
        tmp = tmp.to_s.gsub("\r\r", "\r")
        # normal new line feeds
        tmp = tmp.to_s.gsub("\r\n", "\n")
        #  remove colors
        tmp.gsub!(/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]/, "")
        # bash
        # zsh
        tmp.gsub!(/\x1B\[\d*?[ABCDsuKJ]/, '')
        tmp.gsub!(/>\.\.\.\.\s{65,79}/, "")
        # ksh
        tmp.gsub!("\r\$\s", "")
        tmp.delete!("\b")
        tmp.delete!("\a")
        tmp.gsub!(/\s{79}</, "")
        # remove all \r plus remove the last character before (zsh)
        tmp.gsub!(/.\r/, "")
        tmp
      end

      def do_encoding_pty(string)
        string.gsub(" \r", '')
      end

      #
      # Verbose version of #print_debug
      #
      def vprint_debug(msg)
        print_debug(msg) if @verbose == true
      end

      def print_debug(string)
        $stdout.puts(string)
      end
    end
  end
end
