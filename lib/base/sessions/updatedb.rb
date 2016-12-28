# Advanced Post Exploitation
# adding support for updatedb like function for cached search of files
module Msf
  module Sessions
    module Updatedb
      attr_accessor :updatedb
      #
      # creates an updatedb database
      # (it searches for all files on the system; executes "ls -l" and uses this output as "database")
      # you could define an extra root directory (default is "/")
      # you can define a file with the output of the command (for faster tests)
      # Note: running this command on / can take a while (depending on the system).
      #
      def locate_updatedb(rootdir='/', stored_file=nil, timeout=(60 * 60 * 15))
        return true if @updatedb
        #
        # TODO
        # ignoring some directories might be usefull for better performance
        # ignore:
        #        /proc
        #        /sys
        #        /dev (maybe)
        #  good idea? yes/no
        if stored_file.nil?
          tmp_timeout = 20 # more timeout?
          #cmd       = "find #{rootdir} -type f -exec ls -l {} \\;" + " 2>/dev/null"
          cmd = "find #{rootdir} -wholename '/proc' -prune  -o -wholename '/sys' -prune  -o -wholename '/dev' -prune -o -ls" + " 2>/dev/null"
          print_debug("Creating an UpdateDB - this might take a while...... running command: #{cmd}")
          db = shell_command_token(cmd, tmp_timeout, timeout)
        else
          db = ::File.read(stored_file)
        end
        @updatedb={}
        db.each_line do | line |
          values   = line.split(" ")
          if values[2].to_s.match(/^(d|c|b|l|s|-)/) && values[10].to_s.match(/^(\/|.\/)/)
            path     = values[10..values.length].join(" ")
            metadata = values[2..9].join(" ")
            @updatedb[path] =  metadata
          elsif values[2].to_s.match(/^(d|c|b|l|s|-)/) && values[9].to_s.match(/^(\/|.\/)/)
            path     = values[9..values.length].join(" ")
            metadata = values[2..8].join(" ")
            @updatedb[path] =  metadata
          elsif  values[0].to_s.match(/^(d|c|b|l|s|-)/) && values[8].to_s.match(/^(\/|.\/)/)
            # in case using -exec ls -l {} instead of -ls
            path     = values[8..values.length].join(" ")
            metadata = values[0..7].join(" ")
            @updatedb[path] =  metadata
          else
            #puts "[ERROR]\t#{line}"
            # TODO/TOCHECK
          end
        end
        true
      end
      #
      # checks if an updatedb database already exists
      #
      def locate_updatedb?
        if @updatedb
          true
        else
          false
        end
      end
      #
      # the updatedb database
      # (output of the "find" command)
      #
      def updatedb
        @updatedb
      end
      #
      # checks if a files exists in updatedb
      #
      def updatedb_file_exists?(file)
        @updatedb.key?(file)
      end
      #
      # checks if a directory exists in db
      #
      def updatedb_dir_exists?(file)
        @updatedb.keys.each do | path |
          # filter out file
          if @updatedb.key?(file)
            if @updatedb[file][0,1] == 'd'
              return true
            else
              return false
            end
          end
          return true if path.start_with? file
        end
        false
      end
      #
      # returns metadata + filename of a file
      # like a cached ls
      #
      def updatedb_file_ls(file)
        updatedb[file]
      end
      #
      # returns the owner of a file
      #
      def updatedb_file_user(file)
        meta = updatedb_file_ls(file)
        if meta
          user = meta.split(" ")[2]
          user
        else
          nil
        end
      end
      #
      # returns the group owner of a file
      #
      def updatedb_file_group(file)
        meta = updatedb_file_ls(file)
        if meta.class.to_s == 'String'
          group = meta.split(" ")
          group
        elsif meta.class.to_s == 'Array'
          group = meta[3]
          group
        else
          nil
        end
      end
      #
      # true if user owns this file
      #
      def updatedb_file_user?(file, user)
        owner = updatedb_file_user(file)
        user == owner
      end
      #
      # true if group owns this file
      #
      def updatedb_file_group?(file, group)
        owner = updatedb_file_group(file)
        group == owner
      end
      #
      # returns file permissions of a file
      #
      def updatedb_file_permissions(file)
        meta = updatedb_file_ls(file)
        if meta
          permissions = meta.split(" ")[0]
          permissions
        else
          nil
        end
      end
      def updatedb_file_permissions?(file, perms)
        tmp = updatedb_file_permissions(file)
        if perms.to_i == 0
          #puts "|#{tmp}|==|#{perms}|"
          return tmp == perms
        else
          octal = perms_to_ocal(tmp)
          #puts "#{perms.to_i}==#{octal}"
          return perms.to_i  == octal
        end
      end
      def perms_to_ocal(perms)
        return 0 if perms.nil?
        return 0 unless perms.length == 10
        return 0 if perms.match(/[^rwx\-stdsbcl]/)
        #puts "perms_to_ocal()"
        permissions = perms[1..3], perms[4..6], perms[7..9]
        octal = '0'
        if perms[9] == 't'
          octal = '1'
        end
        if perms[6] == 't'
          octal = '2'
        end
        if perms[3] == 's'
          octal = '4'
        end
        permissions.each do |p|
          tmp = 0
          p.sub!('t', '1')
          p.sub!('s', '1')
          p.sub!('-', '0')
          p.sub!('r', '4')
          p.sub!('w', '2')
          p.sub!('x', '1')
          p.each_char do |c|
            tmp = tmp + c.to_i
          end
          octal << tmp.to_s
        end
        octal.to_i
      end
      #
      # searches all files with special permissions
      #
      def updatedb_search_permissions(perms)
        file_list = []
        updatedb.each_pair  do | file, meta |
          if meta
            permissions = meta.split(" ")[0]
            if permissions.match(perms)
              file_list << file
            end
          end
        end
        file_list
      end
      #
      # searches all suid files
      #
      def updatedb_search_suid
        perms = "^-[rws][rws][rws]"
        updatedb_search_permissions(perms)
      end
      #
      # searches all files writeable for every user
      #
      def updatedb_search_world_writeable
        perms = "^[-d][rst-]w.[rst-]w.[rst-]w"
        updatedb_search_permissions(perms)
      end
      #
      # searches for files (pattern or regex)
      #
      def updatedb_search(search)
        file_list = []
        @updatedb.each_pair  do | file, _meta |
          if file.match(search)
            file_list << file
          end
        end
        file_list
      end
    end
  end
end

module Msf
  class Post
    # module Staekka
    module Updatedb
      def find_files(search)
        if datastore['USE_UPDATEDB'] == false
          return []
        end
        if datastore['FILES'] == false
          # do not search for these files
          return []
        else
          unless session.locate_updatedb?
            m = framework.post.create("unix/general/updatedb")
            m.datastore['SESSION'] = datastore['SESSION']
            m.options.validate(m.datastore)
            m.run_simple(
              'LocalInput'    => user_input,
              'LocalOutput'    => user_output
            )
          end
          session.updatedb_search(search)
        end
      end
    end
  end
end
