#
# This module checks for contraindication of sucessfully exploitaion - which
# prevents failed exploits, causing noise and loosing your 0days.
# It also can be used for filling your pentest reports by reporting a lack of
# hardening, ...etc
#
#
# TODO: usage of objectdump as alternative to readelf
#
require 'msf/core'
require 'rex'
require 'core/post/unix/commands'
require 'msf/core/post/common'
require 'core/post/staekka/file'
require 'core/post/staekka/unix'
#require 'staekka_path'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Staekka
  include Msf::Post::Staekka::Unix
  include Msf::Post::Unix::Commands

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Kernel Hardening',
                      'Description'   => %q( Check for kernel extra hardings ),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'jot' ],
                      'Version'       => '$Revision: 1 $',
                      'Platform'      => [ 'linux' ],
                      'SessionTypes'  => [ 'shell', 'meterpreter' ]))
    register_options(
      [
        OptBool.new("PAXTEST", [ false, "Exe paxtest (usually it needs upload and compile code on the remote system) Attention: might be logged!", true ]),
        OptString.new("WRITEABLEDIR", [ true, "A directory where we can write files (must not be mounted noexec)", "/var/tmp" ]),
        OptString.new("BINARY", [ true, "A binary to test (like /usr/sbin/sshd)",  "none"]),
        OptString.new("PID", [ true, "A PID of a process to test", "none"]),
        # TODO: more functionality
        OptBool.new("PS_ALL", [ true, "All running processes",  false]),
        OptBool.new("PS_NET", [ true, "All processes on network listen mode", false]),
      ], self
    )

    @ltype = 'generic.environment'
    @output = ''
  end

  def run
    pax_test if datastore["PAXTEST"] == true
    if installed?("readelf")
      check_fortify
      if datastore["Binary"] != 'none'
        binary = datastore["Binary"]
        check_binary(binary)
      end
      if datastore["Pid"] != 'none'
        pid = datastore["Pid"]
        check_elf_proc(pid)
      end
      if datastore["PS_all"] == true
        get_running_processes.each do |p|
          check_elf_proc(p)
        end
      end
      if datastore["PS_net"] == true
        get_listing_processes.each do |p|
          check_elf_proc(p)
        end
      end
    else
      print_error "readelf not installed"
    end
    store_loot(@ltype, "text/plain", session, @output) if @output
    print_line @output if @output
  end

  def check_binary(binary)
    check_fortify_file(binary)
    check_elf_file(binary)
  end

  def pax_test
    cd datastore["WritableDir"]
    if installed?("paxtest")
      out = cmd_exec("paxtest blackhat")
      print_status out
      @output << out
      rm "paxtest.log"
    elsif installed?("tar") && installed?("make") && compiler?
      vprint_status("Uploading and compiling paxtest")
      tmpdir = "#{datastore['WritableDir']}/#{Rex::Text.rand_text_alpha(8)}"
      mkdir tmpdir
      remotefile = tmpdir + "/" + Rex::Text.rand_text_alpha(8) + ".tar.gz"
      localfile =  File.expand_path(File.join(Msf::Config.staekka_path, 'data', 'post', 'linux', 'paxtest_src.tar.gz'))
      upload_file(localfile, remotefile)
      if file_exist?(remotefile)
        cd tmpdir
        cmd_exec("tar xfz #{remotefile}")
        cd "#{tmpdir}/paxtest*"
        cmd_exec("make linux")
        out = cmd_exec("./paxtest blackhat")
        print_status out
        @output << out
        cd datastore["WritableDir"]
        rm tmpdir
      else
        print_error "could not upload #{remotefile}"
      end
    else
      print_error "necessary tools for compiling are not installed"
    end
  end

  def check_elf_file(file)
    unless readable?(file)
      print_error "#{file} not readable"
      return
    end
    unless grep("ELF", { cmd: "file #{file}" }, true)
      print_error "#{file} an ELF file"
      return
    end

    check_file_relo(file)
    check_file_canary(file)
    check_file_nx(file)
    check_file_pie(file)
    check_file_rpath(file)
    check_file_runpath(file)
  end

  # check for RELRO support
  def check_file_relo(file, reporting = "all")
    if grep("GNU_RELRO", { cmd: "readelf -l #{file}" }, true)
      if grep("BIND_NOW", { cmd: "readelf -d #{file}" }, true)
        if reporting == "all" || reporting == "secure"
          print_good "#{file}:\tFull RELRO"
          @output << "#{file}:\tFull RELRO\n"
        end
        true
      else
        if reporting == "all" || reporting == "insecure"
          print_status "#{file}:\tPartial RELRO"
          @output << "#{file}:\tPartial RELRO\n"
        end
        false
      end
    else
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tNo RELRO"
        @output << "#{file}:\tNo RELRO\n"
      end
      false
    end
  end

  # check for stack canary support
  def check_file_canary(file, reporting = "all")
    if readable?(file)
      if grep("Symbol table", { cmd: "readelf -s #{file}" }, true)

        if grep("__stack_chk_fail", { cmd: "readelf -s #{file}" }, true)
          if reporting == "all" || reporting == "secure"
            print_good "#{file}:\tCanary found"
            @output << "#{file}:\tCanary found\n"
          end
          true
        else
          if reporting == "all" || reporting == "insecure"
            print_status "#{file}:\tNo canary found"
            @output << "#{file}:\tNo canary found\n"
          end
          false
        end
      else
        if reporting == "all" || reporting == "insecure"
          print_status "#{file}:\tNo symbol table found"
          @output << "#{file}:\tNo symbol table found\n"
        end
        false
      end
    else
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tNo canary found"
        @output << "#{file}:\tNo canary found\n"
      end
      false
    end
  end

  # check for NX support
  def check_file_nx(file, reporting = "all")
    out = grep("GNU_STACK", { cmd: "readelf -W -l #{file}" }, true)
    if out.to_s.match('RWE')
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tNX disabled"
        @output << "#{file}:\tNX disabled\n"
      end
      false
    else
      if reporting == "all" || reporting == "secure"
        print_good "#{file}:\tNX enabled"
        @output << "#{file}:\tNX enabled\n"
      end
      true
    end
  end

  # check for PIE support
  def check_file_pie(file, reporting = "all")
    if grep("Type:\s*EXEC", { cmd: "readelf -h #{file}" }, true)
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tNo PIE"
        @output << "#{file}:\tNo PIE\n"
      end
      true
    else
      if grep("Type:\s*DYN", { cmd: "readelf -h #{file}" }, true)
        if grep('(DEBUG)', { cmd: "readelf -d #{file}" }, true)
          if reporting == "all" || reporting == "secure"
            print_good "#{file}:\tPIE enabled"
            @output << "#{file}:\tPIE enabled\n"
          end
          true
        else
          if reporting == "all" || reporting == "insecure"
            print_status "#{file}:\tDSO"
            @output << "#{file}:\tDSO\n"
          end
          false
        end
      else
        if reporting == "all" || reporting == "insecure"
          print_status "#{file}:\tNot an ELF file"
          @output << "#{file}:\tNot an ELF file\n"
        end
        false
      end
    end
  end

  # check for rpath
  def check_file_rpath(file, reporting = "all")
    if grep("rpath", { cmd: "readelf -d #{file}" }, true)
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tRPATH"
        @output << "#{file}:\tRPATH\n"
      end
      false
    else
      if reporting == "all" || reporting == "secure"
        print_good "#{file}:\tNo RPATH"
        @output << "#{file}:\tNo RPATH\n"
      end
      true
    end
  end

  # check for run path
  def check_file_runpath(file, reporting = "all")
    if grep("rpath", { cmd: "readelf -d #{file}" }, true)
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tRUNPATH"
        @output << "#{file}:\tRUNPATH\n"
      end
      false
    else
      if reporting == "all" || reporting == "secure"
        print_good "#{file}:\tNo RUNPATH"
        @output << "#{file}:\tNo RUNPATH\n"
      end
      true
    end
  end

  def check_fortify
    libc = get_path_libc
    return nil unless libc
    @fortify_functions = get_fortify_functions
    if @fortify_functions.empty?
      print_status "No FORTIFY_SOURCE support available (libc)"
    else
      print_good "FORTIFY_SOURCE support available (libc)"
    end
  end

  def get_fortify_functions
    functions = []
    libc = get_path_libc
    return nil unless libc
    out = grep("_chk@@", cmd: "readelf -s #{libc}")
    out.each do |line|
      file = line.split(" ").to_a[7]
      file.sub(/^__/, "")
      file.gsub!(/_chk@.*/, "")
      functions << file
    end
    functions
  end

  def get_path_libc
    files = { 1 => "/lib/libc.so.6",
              2 => "/lib64/libc.so.6",
              3 => "/lib/x86_64-linux-gnu/libc.so.6",
              4 => "/lib/i386-linux-gnu/libc.so.6" }
    files.keys.sort.each do |key|
      file = files[key]
      return file if readable?(file)
    end
    nil
  end

  def check_fortify_file(file)
    file_functions = get_file_functions(file)
    if @fortify_functions.nil?
      check_fortify
    end
    file_functions.each do |func|
      next unless @fortify_functions.grep(func)
      print_good "Fortify (#{file}): #{func}" if func.match("chk")
    end
  end

  def get_file_functions(file)
    functions = []
    out = cmd_exec("readelf -s #{file}")
    out.each_line do |line|
      line.chomp!
      file = line.split(" ").to_a[7]
      next if file.nil?
      file.sub(/^__/, "")
      file.gsub!(/@.*/, "")
      functions << file
    end
    functions
  end

  #############################################################################
  def check_elf_proc(pid)
    file = "/proc/#{pid}/exe_"
    if readable?(file)
      check_file_relo(file)
      check_file_canary(file)
      check_file_nx(file)
      check_file_pie(file)
      check_file_rpath(file)
      check_file_runpath(file)
      check_proc_pie(file)
    end
    check_proc_pax(pid)
    libs = check_proc_getlibs(pid)
    print_status("Libraries: #{libs.join(', ')}") unless libs.nil?
  end

  # check for PIE support
  def check_proc_pie(file, reporting = "all")
    if grep("Type:\s*EXEC", { cmd: "readelf -h #{file}" }, true)
      if reporting == "all" || reporting == "insecure"
        print_status "#{file}:\tNo PIE"
        @output << "#{file}:\tNo PIE\n"
      end
      true
    else
      if grep("Type:\s*DYN", { cmd: "readelf -h #{file}" }, true)
        if grep('(DEBUG)', { cmd: "readelf -d #{file}" }, true)
          if reporting == "all" || reporting == "secure"
            print_good "#{file}:\tPIE enabled"
            @output << "#{file}:\tPIE enabled\n"
          end
          true
        else
          if reporting == "all" || reporting == "insecure"
            print_status "#{file}:\tDynamic Shared Object"
            @output << "#{file}:\tDynamic Shared Object\n"
          end
          false
        end
      else
        if reporting == "all" || reporting == "insecure"
          print_status "#{file}:\tNot an ELF file"
          @output << "#{file}:\tNot an ELF file\n"
        end
        false
      end
    end
  end

  def check_proc_pax(pid, _reporting = "all")
    file = "/proc/#{pid}/status"
    unless readable?(file)
       vprint_error"cannot read #{file}"
      return
    end
    #		unless empty?(file)
    #			#print_debug "cannot read #{file}"
    #			return
    #		end
    out = grep('PaX:', cmd: "cat #{file}").to_s
    pageexec = out[5, 1]
    segmexec = out[9, 1]
    mprotect = out[7, 1]
    randmmap = out[8, 1]
    if (pageexec == 'P' || segmexec == 'S') && (mprotect == 'M' || randmmap == 'R')
      print_good "#{file}:\tPaX enabled"
    elsif (pageexec == 'p' && segmexec == 's') && (randmmap == 'R')
      print_status "#{file}:\tPaX ASLR only"
    elsif (pageexec == 'P' || segmexec == 'S') && (mprotect == 'm' || randmmap == 'R')
      print_status "#{file}:\tPaX mprot off"
    elsif (pageexec == 'P' || segmexec == 'S') && (mprotect == 'M' || randmmap == 'r')
      print_status "#{file}:\tPaX ASLR off"
    elsif (pageexec == 'P' || segmexec == 'S') && (mprotect == 'm' || randmmap == 'r')
      print_status "#{file}:\tPaX NX only"
    else
      print_status "#{file}:\tPaX disabled"
    end
  end

  def check_proc_getlibs(pid)
    libs = []
    file = "/proc/#{pid}/maps"
    unless readable?(file)
      vprint_error "cannot read #{file}"
      return nil
    end
    #		unless empty?(file)
    #			#print_debug "cannot read #{file}"
    #			return nil
    #		end
    command = "awk '{ print $6 }' #{file}|grep '/'|sort -u"
    cmd_exec(command).to_s.each_line do |line|
      line = line.to_s
      line.chomp!
      # checking for non readable (waiting of time)
      if (line.ends_with? "Permission denied") or (line.ends_with? "(Permission denied)")
        return([])
      end
      libs << line if grep("ELF", { cmd: "file #{line}" }, true)
    end
    libs
  end

  #####################################
  def get_running_processes
    list = {}
    command = "ps -e"
    cmd_exec(command).to_s.each_line do |line|
      pid = line.split(" ")[0]
      pid.strip!
      next if pid.match(/[^[:digit:]]/)
      #
      # Performance hack:
      # avoid testing the same command again and again
      # and ignoring processes we do not have access (not root?)
      #
      file = "/proc/#{pid}/cmdline"
      if readable?(file)
        cmd = cmd_exec("cat #{file}")
        list[cmd] = pid
      end
    end
    list.values
  end

  def get_listing_processes
    list = {}
    pid_list = []
    if installed? "lsof"
      command = "lsof -i"
      cmd_exec(command).to_s.each_line do |line|
        if line.match("LISTEN")
          pid = line.split(" ")[1]
          pid_list << pid.strip
        end
      end
    else
      command = "netstat -nap"
      cmd_exec(command).to_s.each_line do |line|
        # TCP
        if line.start_with?("tcp") && (line.match " LISTEN ")
          tmp = line.split(" ")[6]
        elsif line.start_with?("udp")
          tmp = line.split(" ")[3]
          tmp = line.split(" ")[5] if tmp.match(/:\d*/)
        else
          next
        end
        next if tmp.nil?
        if tmp.match(/(\d*)\//)
          pid = Regexp.last_match[1]
          pid_list << pid.strip
        end
      end
    end

    pid_list.each do |pid|
      if pid.match(/[^[:digit:]]/)
        print_error "Wrong PID format: #{pid}"
        next
      else
        #
        # Performance hack:
        # avoid testing the same command again and again
        # and ignoring processes we do not have access (not root?)
        #
        file = "/proc/#{pid}/cmdline"
        if readable?(file)
          cmd = cmd_exec("cat #{file}")
          list[cmd] = pid
        end
      end
    end
    list.values
  end
end
