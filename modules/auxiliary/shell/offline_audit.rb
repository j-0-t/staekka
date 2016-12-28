#
#
#

require 'msf/core'
require 'base/sessions/offline'

class MetasploitModule < Msf::Auxiliary
  attr_accessor :sock

  def initialize
    super(
        'Name'        => 'Offline Shell',
        'Description' => %q(
        This module allows to perform tests/audits with pre-collected data.
                ),
        'Author'      => 'jot',
        'License'     => MSF_LICENSE #
    )
    register_options(
      [
        OptPath.new('DATADIR', [true, "Directory with collected data", "/tmp/audit"]),
        OptString.new('DATATYPE', [false, "Structure of the offline data directory", "default"])
      ], self.class
    )
  end

  def run
    # setting default RHOST to localhost
    datastore['RHOST'] = '127.0.0.1'
    info = 'Offline'
    ds_merge = {}
    datadir = datastore['DATADIR']
    datatype = datastore['DATATYPE']

    # merge_me = {}

    sess = Msf::Sessions::Offline.new(self)

    sess.offline_path(datadir)
    sess.offline_init('default') if datatype == 'default'

    if datastore['VERBOSE'] || framework.datastore['VERBOSE']
      sess.verbose = true
    end
    sess.set_from_exploit(self)
    sess.info = info

    # Clean up the stored data
    sess.exploit_datastore.merge!(ds_merge)

    # Prevent the socket from being closed
    # obj.sockets.delete(sock)
    # obj.sock = nil if obj.respond_to? :sock

    framework.sessions.register(sess)
    #######
  end
end

# module Msf::Post::Common
#  def cmd_exec(cmd, args=nil, time_out=15)
#    case session.type
#    when /meterpreter/
#      #
#      # The meterpreter API requires arguments to come seperately from the
#      # executable path. This has no effect on Windows where the two are just
#      # blithely concatenated and passed to CreateProcess or its brethren. On
#      # POSIX, this allows the server to execve just the executable when a
#      # shell is not needed. Determining when a shell is not needed is not
#      # always easy, so it assumes anything with arguments needs to go through
#      # /bin/sh.
#      #
#      # This problem was originally solved by using Shellwords.shellwords but
#      # unfortunately, it is retarded. When a backslash occurs inside double
#      # quotes (as is often the case with Windows commands) it inexplicably
#      # removes them. So. Shellwords is out.
#      #
#      # By setting +args+ to an empty string, we can get POSIX to send it
#      # through /bin/sh, solving all the pesky parsing troubles, without
#      # affecting Windows.
#      #
#      if args.nil? and cmd =~ /[^a-zA-Z0-9\/._-]/
#        args = ""
#      end
#
#      session.response_timeout = time_out
#      process = session.sys.process.execute(cmd, args, {'Hidden' => true, 'Channelized' => true})
#      o = ""
#      while (d = process.channel.read)
#        break if d == ""
#        o << d
#      end
#      o.chomp! if o
#
#      begin
#        process.channel.close
#      rescue IOError => e
#        # Channel was already closed, but we got the cmd output, so let's soldier on.
#      end
#
#      process.close
#    when /shell/
#      o = session.shell_command_token("#{cmd} #{args}", time_out)
#      o.chomp! if o
#    when /offline/
#      o = session.cmd_exec("#{cmd} #{args}")
#    end
#    return "" if o.nil?
#    return o
#  end
#
# end
