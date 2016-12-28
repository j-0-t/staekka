#
# Advanced Post Exploitation
#
require 'banner'
require 'staekka_path'
module Msf
  # Staekka: extending Metasploit with more Linux/Unix focus
  module Staekka
    def staekka_path
      @staekka_path
    end
    def staekka_path=(path)
      @staekka_path=path
    end
  end
end
