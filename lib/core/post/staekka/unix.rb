# Advanced Post Exploitation

module Msf
  class Post
    module Staekka
      #
      # common unix commands
      #
      module Unix
        def enum_user_directories
          if ( session.methods.include? :cache) && session.cache.exists?("user_dirs")
            return session.cache.read("user_dirs")
          end
          user_dirs = ['/', '/root']

          # get all user directories from /etc/passwd
          passwd = read_file("/etc/passwd", false, true)
          passwd.each_line do |passwd_line|
            user_dirs << passwd_line.split(/:/)[5]
          end

          # use getent for non-local users
          if installed?("getent")
            cmd = "getent passwd"
            passwd = cmd_exec(cmd)
            passwd.each_line do |passwd_line|
              user_dirs << passwd_line.split(/:/)[5]
            end
          end

          # also list other common places for home directories in the event that
          # the users aren't in /etc/passwd (LDAP, for example)
          case session.platform
          when 'osx'
            ls('/Users').each do |l|
              l.strip!
              user_dirs << "/Users/#{l}"
            end
          # user_dirs << cmd_exec('ls -m /Users').each_line.map { |l| "/Users/#{l}" }
          else
            ls('/home').each do |l|
              l.strip!
              user_dirs << "/home/#{l}"
            end
            # user_dirs << cmd_exec('ls -m /home').each_line.map { |l| "/home/#{l}" }
          end

          user_dirs.flatten!
          user_dirs.compact!
          user_dirs.sort!
          user_dirs.uniq!

          session.cache.add("user_dirs", user_dirs) if  session.methods.include? :cache
          user_dirs
        end
      end
    end
  end
end
