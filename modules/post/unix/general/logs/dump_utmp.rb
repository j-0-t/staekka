# $LOAD_PATH.push(staekka_path() + '/external/bindata/lib')
# $LOAD_PATH.push "#{ENV['STAEKKA_PATH']}/external/bindata/lib"
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

#$LOAD_PATH.push "../staekka/external/bindata/lib"




class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Dump Utmp Logfiles',
        'Description'   => %q(Dump utmp  log files as text),
        'Author'        => [ 'jot'],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptBool.new('USE_UPDATEDB',  [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptPath.new('FILES',  [ false, 'A special log file']),
      ], self.class)
  end

  def run
    all_log_files.each do |file|
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
      else # less
        # OK
      end

      dump_utmp(file)
      #
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
    if readable?(file)
      true
    else
      print_error "Need read  permissions for #{file} for changing it! Cannot go on"
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
    logfile = StringIO.new(read_file(file, true, false))
    utmp = get_utmp_type(logfile)
    if utmp.nil?
      print_error "Unkown UTMP structure for #{file}"
      return
    end
    out = ''
    utmp.each_entry(logfile) do | utmp, data |
      out << utmp.print_entry(data)
    end
    print_status out
  end

end

