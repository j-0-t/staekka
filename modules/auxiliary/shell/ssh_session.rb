# Advanced Post Exploitation
#
#
#

require 'msf/core'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'

require Msf::Config.staekka_path + '/lib/base/sessions/ssh_session'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell

  include Msf::Auxiliary::Scanner

  attr_accessor :sock

  def initialize
    super(
      'Name'        => 'Interactive SSH Shell',
      'Description' => %q(
        Login using SSH
      ),
      'Author'      => 'jot',
      'License'     => MSF_LICENSE #
    )
    register_options(
      [
        Opt::RPORT(22),
        OptBool.new('INTERACTIVE', [false, "Start an interactive shell", false]),
        OptString.new('SSH_KEYFILE', [false, 'Path to unencrypted SSH public key', '']),
        OptString.new('CMD', [false, "The local program/shell to use", "default"]),
        OptString.new('STOP', [false, "The string for stopping the interactive modus", "default"]),
        OptString.new('LOGFILE', [false, "Log stdin/stdout into this file; 'none' for disable logging", "default"])
      ], self.class
    )
    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptString.new('SSH_KNOWN_HOST_FILE', [ false, 'Path to a file containing the public key of the SSHD', false]),
        OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 30])
      ]
    )
  end

  def run
    ssh_options = {}

    ssh_options[:host_name] = datastore['RHOSTS']
    ssh_options[:port] = datastore['RPORT']
    ssh_options[:user] = datastore['USERNAME']
    ssh_options[:password] = datastore['PASSWORD']
    ssh_options[:config] = false
    #ssh_options[:encryption] = ["blowfish-cbc", "3des-cbc"]
    ssh_key = datastore['SSH_KEYFILE'].to_s.strip
    unless ssh_key.empty?
      ssh_options[:keys] = ssh_key
      # ssh_options[:keys_only] = true
    end
    known_host_file = datastore['SSH_KNOWN_HOST_FILE'].to_s.strip
    unless known_host_file.empty?
      ssh_options[:user_known_hosts_file] = known_host_file
      # ssh_options[:paranoid] = true
    end
    # ssh_options[:verbose] = :debug

    # vprint_info "SSH_OPTIONS: #{ssh_options.inspect}"

    cmd = datastore['CMD']
    cmd = nil if cmd == "default"
    stop_string = datastore['STOP']
    stop_string = nil if stop_string == "default"
    logfile = datastore['LOGFILE']
    logfile = nil if logfile == "none"

    #    merge_me = {
    #      'USERPASS_FILE' => nil,
    #      'USER_FILE'     => nil,
    #      'PASS_FILE'     => nil,
    #      'USERNAME'      => result.credential.public,
    #      'PASSWORD'      => result.credential.private
    #    }

    merge_me = {}
    $stdout.puts "__LOG #{logfile}"
    # sock = Msf::Sessions::PTY::PtySocket.new(cmd, stop_string, logfile)
    # sock = Msf::Sessions::SshSession::SecureShell.new(ssh_options, cmd, stop_string, logfile)

    raise "Net::SSH connection error" if check_net_ssh_bug(ssh_options) == false

    sock = Msf::Sessions::SshSession::SecureShell.new(cmd, stop_string, logfile, ssh_options)

    print_status("Logfile: #{sock.logfile}")
    interactive = if datastore['INTERACTIVE'] == true
                    true
                  else
                    false
                  end
    start_ssh_session(self, "SSH: ", merge_me, false, sock, interactive)
  end

  def start_ssh_session(obj, info, ds_merge, _crlf = false, sock = nil, interactive = false)
    # if crlf
    # Windows telnet server requires \r\n line endings and it doesn't
    # seem to affect anything else.
    # obj.sock.extend(CRLFLineEndings)
    # end

    sock ||= obj.sock
    sess = Msf::Sessions::SshSession.new(sock)
    if datastore['VERBOSE'] || framework.datastore['VERBOSE']
      sess.verbose = true
    end
    sess.set_from_exploit(obj)
    sess.info = info

    # Clean up the stored data
    sess.exploit_datastore.merge!(ds_merge)

    # Prevent the socket from being closed
    obj.sockets.delete(sock)
    obj.sock = nil if obj.respond_to? :sock

    framework.sessions.register(sess)
    sess.process_autoruns(datastore)
    if interactive == true
      $stdout.puts "starting Interactive...."
      sess.interactive
    end
    sess.new_session
    sess
  end

  def check_net_ssh_bug(options)
    ssh_options = options
    ssh_options[auth_methods: []] # no auth method
    begin
      ssh = Net::SSH.start(nil, nil, ssh_options)
      true
    rescue Net::SSH::AuthenticationFailed
      true
    rescue Net::SSH::Exception => e
      print_error "Cannot connect to #{options[:host_name]}:#{options[:port]}. \n#{e}\nThis might be  because Net::SSH. OpenSSH config settings are \"Ciphers\" and \"KexAlgorithms\""
      false
    end
  end
end
