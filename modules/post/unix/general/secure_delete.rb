#
require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'core/post/staekka'
require 'core/post/staekka/file'
require 'core/post/unix/commands'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  # include Msf::Post::Staekka::File
  include Msf::Post::Unix::Commands

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Secure Delete',
                      'Description'   => %q{(fast) overwriting and deleting files (and directories)},
                      'Author'        => [ 'jot'],
                      'SessionTypes'  => [ 'shell' ]))
    register_options(
      [
        OptString.new('RFILE', [ true, 'Remote file or directory'])
      ], self.class
    )

    @post_data = nil
  end

  def run
    path = datastore['RFILE']
    if secure_delete(path, true)
      vprint_status("#{path} is deleted")
    else
      print_error("#{path} had not been deleted!")
    end
  end

  #####################
  def secure_delete(path, force = true)
    unless writeable?(path)
      print_error "No write permission for #{path}"
      if force == false
        print_error "Needs to be done manually"
        return false
      else
        print_error "Trying to overwrite it - might fail"
      end
    end
    cmd = find_secure_delete
    if cmd.nil?
      print_error "Cannot secure delete #{path}! no tool for overwriting found. Needs to be done manually!"
      return false
    end

    cmd = cmd.gsub("__FILE__", path)

    out = cmd_exec(cmd)
    vprint_status("Wipe command: #{cmd}\n#{out}")

    if exists? path
      print_error "Cannot delete #{path}!"
      return false
    end
    true
  end

  def find_secure_delete
    #    if session.cache && session.cache.exists?("secure_delete")
    #      return session.cache.read("secure_delete")
    #    end

    command = nil

    #############
    # as deleting files may take while verbose output keeps reading output for avoiding timeouts

    n_pass_overwrite = 3

    if installed? "shred"
      # shred - overwrite a file to hide its contents, and optionally delete it
      # (part of coreutils: should be installed on most linux systems
      #
      # find for recursive
      # shred: overwrite/delete files (no directories)
      #   -f      force:  change permissions to allow writing if necessary
      #   -u      remove:  truncate and remove file after overwriting
      #   -z      zero: add a final overwrite with zeros to hide shredding
      #   -v      verbose: show progress
      #   -n       overwrite N times
      ####
      command = "find __FILE__ -type f -exec  shred -f -u -z -n #{n_pass_overwrite} -v {} \\; ; rm -rf __FILE__"
    elsif installed? "wipe"
      # wipe - secure file deletion utility  http://wipe.sourceforge.net/
      #   -I     disables interaction
      #  -d     delete  after wiping
      #  -r      recursive
      #  -z     zero-out file - performs a single pass of zeros
      #  -p     perform wipe sequence x times
      command = "wipe -I  -d -f -r  -p #{n_pass_overwrite} -z  __FILE__"
    elsif installed? "srm"
      #  srm - securely remove files or directories http://sourceforge.net/projects/srm/
      # -f    force:        ignore nonexistent files, never prompt
      # -r    recursive:  remove the contents of directories recursively
      # -v   verbose
      # -E   US   DoE   compliant   3-pass   overwrite
      command = "srm -f -r -E -v __FILE__"
    elsif installed? "bcwipe"
      # bcwipe - securely erase data from magnetic and solid-state memory http://www.jetico.com
      # -v      verbose:      Explain what is being done.
      # -r       recuresive:  Remove with wiping the contents of directories recursively
      # -f       force:           Force wipe files with no write permissions.  Also suppress interactive mode.
      # -n 1    delay:          Wait  delay  seconds  between  wiping  passes.
      # -me    U.S. DoE 3-pass wiping.
      command = "bcwipe  -v -r -f -n 1 -me __FILE__"
    elsif installed? "dd"
      #
      if exists? "/dev/urandom"
        src = "/dev/urandom"
      elsif exists? "/dev/random"
        src = "/dev/random"
      end
      # get_size = '`stat --printf="%s" __FILE__ `'
      # get_size = '`wc -c  < __FILE__ `'
      # command = "find __FILE__ -type f -exec stat --printf=\"dd if=#{src} of={} bs=1 count=%s\"  {} \\;| sh; rm -f __FILE__"
      command = ""
      n_pass_overwrite.times do
        command << "find __FILE__ -type f -exec stat --printf=\"dd if=#{src} of={} bs=1 count=%s ;\"  {} \\;| sh; "
        command << "sleep 1;" # Wait  delay  of 1 second  between  wiping  passes.
      end

      # rename files to random file names
      # needs dirname: part of coreutils -> usually shred is already installed
      # dirname part of busybox
      if installed? "dirname"
        random = ''
        if installed? "openssl"
          random = 'openssl rand -hex  8'
        elsif installed? "pwgen"
          random = 'pwgen 12 1'
        elsif installed? "makepasswd"
          random = 'makepasswd --chars 16'
        elsif installed? "md5sum"
          random = 'date|md5sum|cut -b 1-8'
        elsif installed? "tr"
          random = 'dd if=/dev/urandom bs=1 count=48 2>/dev/null |tr -cd \'[:alnum:]\''
        end
        unless random.empty?
          command << "find __FILE__ -type f -exec  echo mv {} \\`dirname {}\\`/\\`#{random}\\` \\; |sh;"
        end
      end

      command << "rm -rf __FILE__"
    else
      return nil
    end

    #  chattr:  change file attributes on a Linux file system
    #     -R     Recursively
    #     +s    When  a  file with the 's' attribute set is deleted, its blocks are zeroed and written back to the disk.
    #     +S    When a file with the 'S' attribute set is modified, the changes are written synchronously on the disk
    command = "chattr -R +sS -u  __FILE__; " + command if installed? "chattr"

    # flush file system buffers
    command << "; sync"

    session.cache.add("secure_delete", command)
  end
end
