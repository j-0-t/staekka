# Advanced Post Exploitation
module Msf
  module Sessions
    #
    # More features for interactive shells
    # * some basic commands
    # * adding session support
    #
    module ShellExtensions
      #
      # does the shell has an echo
      # (echo a test string and check if it is in output)
      #
      def echo?
        check_string = "echo_" + ::Rex::Text.rand_text_alpha(32)
        command = "echo #{check_string}"
        out = shell_command(command)
        if out.to_s.match(check_string)
          true
        else
          false
        end
      end

      #
      # getting a (shell) environment variable
      #
      def enviroment_get(key)
        out = shell_command_token("echo $#{key}").to_s.chomp
        # fallback
        # needed for sash
        out = shell_command_token("printenv #{key}").to_s.chomp if out.empty?
        out
      end

      #
      # setting a (shell) environment variable
      #
      def enviroment_set(key, value)
        cmd1 = "set #{key}=\"#{value}\";"
        cmd1 << "export #{key}=\"#{value}\""
        # fallback
        # sash style
        cmd2 = "setenv #{key} \"#{value}\""
        shell_command(cmd1)
        shell_command(cmd2)
      end

      #
      # return the current session id
      #
      def shell_session_id
        @session_id
      end

      #
      # starting a new shell session
      #   -> generating a session id
      #   -> exporting it via XSESSIONID shell environment variable
      #
      def new_session_start
        id_token = ::Rex::Text.rand_text_alpha(32)
        key = 'XSESSIONID'
        enviroment_set(key, id_token)
        if enviroment_get(key).to_s.match(id_token)
          @session_id = id_token
          true
        else
          false
        end
      end

      #
      # tests if it a new shell session
      # true if XSESSIONID is not equal to the current session id (@session_id)
      #
      def new_session?
        return nil unless @session_id
        key = 'XSESSIONID'
        out = enviroment_get(key).to_s
        if out.match(@session_id)
          false
        else
          true
        end
      end

      #
      # does the shell have a tty?
      #
      def tty?
        out = shell_command_token("tty;/bin/tty;/usr/bin/tty")
        return true if out.match "/dev/"
        return false if out.match "not a tty"
        false
      end
    end
  end
end
