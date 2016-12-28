#
# Advanced Post Exploitation

# require 'msf/core/post/file'

module Msf
  class Post
    #
    # Simple commands for Staekka
    #
    module Staekka
      #
      # check if a command was successful
      #
      def cmd_success?(command)
        check_string = ::Rex::Text.rand_text_alpha(12)
        command << " && echo #{check_string}"
        out = cmd_exec(command)
        #if out.to_s.match(check_string)
        if out.to_s.delete("\r").match(check_string)
          true
        else
          false
        end
      end
    end
  end
end
