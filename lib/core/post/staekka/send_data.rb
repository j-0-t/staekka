# Advanced Post Exploitation
module Msf
  class Post
    module Staekka
      #
      # sending special data to $STDIN
      #
      module SendData
        #
        # send a newline "\n"
        #
        def send_newline
          data = "\n"
          session.shell_write(data)
        end

        #
        # send [ctrl]-[c]
        #
        def send_ctrl_c
          data = 3.chr
          session.shell_write(data)
        end

        #
        # send [ctrl]-[d]
        #
        def send_ctrl_d
          data = 4.chr
          session.shell_write(data)
        end

        #
        # send [ctrl]-[z]
        #
        def send_ctrl_z
          data = 26.chr
          session.shell_write(data)
        end

        #
        # send [ctrl]-[escape]
        #
        def send_ctrl_escape
          data = 27.chr
          session.shell_write(data)
        end

        #
        # send a q
        #
        def send_q
          data = "q "
          session.shell_write(data)
        end

        #
        # send a Q
        #
        def send_capital_q
          data = "q"
          session.shell_write(data)
        end

        #
        # send quit
        #
        def send_quit
          data = "quit"
          session.shell_write(data)
        end

        #
        #  send exit
        #
        def send_exit
          data = "exit"
          session.shell_write(data)
        end

        #
        #  send yes
        #
        def send_yes
          data = "yes"
          session.shell_write(data)
        end

        #
        # execute /bin/sh from vi
        #
        def send_vi_shell
          send_ctrl_escape
          data = ":!/bin/sh" + "\n"
          session.shell_write(data)
        end

        #
        # exit vi without saving
        #
        def send_vi_exit_nosave
          send_ctrl_escape
          data = ":q!" + "\n"
          session.shell_write(data)
        end

        #
        # exit vi with saving
        #
        def send_vi_exit_save
          send_ctrl_escape
          data = ":x!" + "\n"
          session.shell_write(data)
        end
      end
    end
  end
end
