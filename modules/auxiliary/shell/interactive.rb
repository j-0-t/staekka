# Advanced Post Exploitation
#
#
#

require 'msf/core'
# require 'staekka/base/sessions/pty'

class MetasploitModule < Msf::Auxiliary
  attr_accessor :sock

  def initialize
    super(
        'Name'        => 'Interactive Expect Shell',
        'Description' => %q(
        This module executes a command you can interact with. You can add this shell session to mfs sessions.
                ),
        'Author'      => 'jot',
        'License'     => MSF_LICENSE #
    )
    register_options(
      [
        OptBool.new('INTERACTIVE', [false, "Start an interactive shell", false]),
        OptString.new('CMD', [false, "The local program/shell to use", "default"]),
        OptString.new('STOP', [false, "The string for stopping the interactive modus", "default"]),
        OptString.new('LOGFILE', [false, "Log stdin/stdout into this file; 'none' for disable logging", "default"])
      ], self.class
    )
    register_advanced_options(
      [
        OptBool.new('LOGTERMINAL', [false, "Start an terminal which monitors the logfile", false])
      ]
    )
  end

  def run
    # setting default RHOST to localhost
    datastore['RHOST'] = 'localhost'
    cmd = datastore['CMD']
    cmd = nil if cmd == "default"
    stop_string = datastore['STOP']
    stop_string = nil if stop_string == "default"
    logfile = datastore['LOGFILE']
    logfile = nil if logfile == "none"

    merge_me = {}
    sock = Msf::Sessions::PTY::PtySocket.new(cmd, stop_string, logfile)
    print_status("Logfile: #{sock.logfile}")

    interactive = if datastore['INTERACTIVE'] == true
                    true
                  else
                    false
                  end
    start_pty_session(self, "PTY: ", merge_me, false, sock, interactive)
  end

  def start_pty_session(obj, info, ds_merge, _crlf = false, sock = nil, interactive = false)
    # if crlf
    # Windows telnet server requires \r\n line endings and it doesn't
    # seem to affect anything else.
    # obj.sock.extend(CRLFLineEndings)
    # end

    sock ||= obj.sock
    sess = Msf::Sessions::PTY.new(sock)
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
    if datastore['LOGTERMINAL'] == true
      sock.start_tailf
    end

    if interactive == true
      $stdout.puts "starting Interactive...."
      sess.interactive
    end
    sess.new_session
    sess
  end
end
