# Advanced Post Exploitation

module Msf
  class Post
    module Unix
      #
      # common unix commands
      #
      module Commands
        # include Msf::Post::File
        include Msf::Sessions::Updatedb

        #
        # make directory
        #
        def mkdir(dir)
          cmd_exec("mkdir -p #{dir}")
        end

        #
        # touch file
        # * create file
        # * or set timestamp to reference file
        #
        def touch(file, reference = nil)
          unless reference
            command = "touch #{file}"
            return cmd_exec(command)
          end
          #############
          # ctime
          #   needs root
          out = cmd_exec("stat #{file}")
          tmp = out.match(/Access: \(\d\d\d\d\//)
          if tmp
            perms = tmp[1]
            if perms && perms.match(/^[0124567]*$/)
              save_date = cmd_exec("date")
              cmd_exec("chmod #{perms} #{file}")
              cmd_exec("date -s #{save_date}")
            end
          end
          command = "touch -r #{reference} #{file}"
          cmd_exec(command)
        end

        #
        # remove/delete file
        # (normal "rm" not wiping the file!)
        #
        def rm(file)
          cmd_exec("rm -rf #{file}")
        end

        #
        # copy file/directory
        #
        def cp(from_file, to_file)
          cmd_exec("cp -rf #{from_file} #{to_file}")
        end

        #
        # move file/directory
        #
        def mv(from_file, to_file)
          cmd_exec("mv -f #{from_file} #{to_file}")
        end

        #
        # get the current directory
        #
        def pwd
          cmd_exec("pwd")
        end

        #
        # change to directory
        #
        def cd(dir = nil)
          cmd_exec("cd #{dir}")
        end

        #
        # reads a file
        #
        def cat(file)
          cmd_exec("cat #{file}")
        end

        #
        # gets contents of a directory and returns an array
        #
        def ls(directory)
          out = []
          tmp = cmd_exec("ls -a -m #{directory}")
          tmp = session.remove_colors(tmp)
          if tmp
            tmp.delete!("\r")
            tmp.delete!("\n")
            tmp.split(/,\s{0,1}/).each do |f|
              next if f.empty?
              next if f == './'
              next if f == '../'
              next if f == '.'
              next if f == '..'
              out << f
            end
           end
          out
        end

        #
        # search for a string and returns all matches
        # * target{:file}    # inside a file
        # * target{:cmd}     # inside the command output
        # * target{:string}  # inside a string
        # example: grep(":0:0:",{:file=>"/etc/passwd"})
        # example: grep(":0:0:",{:cmd=>"cat /etc/passwd"})
        #
        def grep(search, target, bool = false)
          data    = ''
          result  = []
          # rx = Regexp.new(search, Regexp::MULTILINE)
          rx = Regexp.new(search)
          if target.class.to_s == 'Hash'
            if target[:file]
              file = target[:file]
              data = cat(file) if readable?(file)
            end
            data = target[:string].to_s if target[:string]
            data = cmd_exec(target[:cmd]) if target[:cmd]
          end
          data = target if target.class.to_s == 'String'
          data.each_line do |line|
            result << line.chomp if rx.match(line)
          end
          if bool == true
            if result.empty?
              return false
            else
              return true
            end
          end
          result
        end

        # kills a program
        # * pid (integer)
        # * command (string) # using killall
        #
        # TODO: killall -> ps|grep|kill
        #
        def kill(target, signal = 9)
          kill_signal = " -#{signal}" if signal

          cmd = if target.class.to_s == "String"
                  "killall #{target} #{kill_signal}"
                else
                  "kill #{target} #{kill_signal}"
                end
          cmd_exec(cmd)
        end

        #
        # shows the OS
        #
        def uname
          if (session.methods.include? :cache) && session.cache.exists?("uname")
            return session.cache.read("uname")
          else
            option = '-a'
            out = cmd_exec("uname #{option}")
            session.cache.add("uname", out)
            out
          end
        end

          # TODO
          # ps
          # netstat
          # ifconfig

          \

        #####################

        #
        # a list of default paths with exeutables
        # ENV[PATH]
        #
        def get_all_path
          # some default directories
          env_paths = []
          env_paths << "/bin"
          env_paths << "/usr/bin"
          env_paths << "/usr/local/bin"
          env_paths << "/sbin"
          env_paths << "/usr/sbin"
          env_paths << "/usr/local/sbin"
          env_paths << "/opt/bin"
          env_paths += cmd_exec("echo $PATH").split(":")
          env_paths.uniq
        end

        #
        # checks if a tool is installed
        # (if it exists inside of the PATH)
        #
        def installed?(tool)
          # first: check with updatedb
          if session.locate_updatedb? == true
            out = ''
            if (session.methods.include? :cache) && session.cache.exists?("ls_path")
              out = session.cache.read("ls_path")
            else
              out = ''
              env_paths = get_all_path
              for path in env_paths
                out << session.updatedb_search(path).join("\n").to_s
              end
            end
            session.cache.add("ls_path", out) if session.methods.include? :cache

            out.each_line do |line|
              line.chomp!
              return line if line =~ /\/#{tool}$/
            end
          end

          # second: if cache run ls for every path once and cache it
          if session.methods.include? :cache
            out = ''
            if session.cache.exists?("ls_path")
              out = session.cache.read("ls_path")
            else
              env_paths = get_all_path
              # ls:
              #  -m     fill width with a comma separated list of entries
              cmd = "/bin/ls -m"
              for path in env_paths
                # adding timeout because it may need some time if many
                # tools are installed
                # out << cmd_exec("#{cmd} #{path}/*", 20, 60 * 2)
                tmp = session.shell_command_token("#{cmd} #{path}/*", 20, 60 * 2)
                tmp.split(',').each do |tmp_tool|
                  tmp_tool.chomp!
                  tmp_tool.strip!
                  out << tmp_tool + "\n"
                end
              end
              # out.gsub!("\t", "\n")
              session.cache.add("ls_path", out)
            end
            out.each_line do |line|
              line.chomp!
              return line if line =~ /\/#{tool}$/
            end

            return false
          end

          # third: fallback: using traditional which
          out = cmd_exec("which #{tool}")
          if out[0, 1] == '/'
            return out
          else
            return nil
          end
        end

        #
        # checks if a C compiler is installed
        # if verify is true it compiles and executes a small test programm
        #
        def compiler?(verify = false, writeable_directory = false)
          if (session.methods.include? :cache) && session.cache.exists?("compiler?")
            return session.cache.read("compiler?")
          end
          writeable_directory = '/var/tmp/' unless writeable_directory == true
          compilers = ['gcc', 'cc', 'tcc', 'pcc']
          compilers.each do |tool|
            next unless installed?(tool)
            if verify == true

              tmp_file = writeable_directory.to_s + ::Rex::Text.rand_text_alpha(12)
              tmp_file_c = tmp_file + '.c'
              match_string = ::Rex::Text.rand_text_alpha(32)
              test_c = "#include <stdio.h>\nint main(void){printf(\"#{match_string} %c\",0x0a);return 0;}"
              test_c.each_line do |line|
                cmd_exec("echo '#{line}'>>#{tmp_file_c}")
              end
              compile = "#{tool} #{tmp_file_c} -o #{tmp_file}"
              cmd_exec(compile)
              out =  cmd_exec(tmp_file)
              rm tmp_file
              rm tmp_file_c
              if out.match(match_string)
                session.cache.add("compiler?", tool) if session.methods.include? :cache
                return tool
              end
            else
              session.cache.add("compiler?", tool) if session.methods.include? :cache
              return tool
            end
          end
          session.cache.add("compiler?", false) if session.methods.include? :cache
          false
        end
      end
    end
  end
end
