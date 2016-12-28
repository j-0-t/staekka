##
# This module checks for contraindication of sucessfully exploitaion - which
# prevents failed exploits, causing noise and loosing your 0days.
# It also can be used for filling your pentest reports by reporting a lack of
# hardening, ...etc
#
##

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
                      'Name'          => 'Kernel Hardening',
                      'Description'   => %q( Check for kernel extra hardings ),
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'jot' ],
                      'Version'       => '$Revision: 1 $',
                      'Platform'      => [ 'linux', 'windows' ],
                      'SessionTypes'  => [ 'shell', 'meterpreter' ]))
    @ltype = 'generic.environment'
    @output = ''
  end

  def run
    check_kernel
    # store_loot(@ltype, "text/plain", session, @output) if @output
    print_line @output if @output
  end

  #############################################################################
  def check_kernel
    check_cpu
    sysctl
    check_config
    check_grsecurity
    check_selinux
    check_appamor
  end

  def sysctl
    sysctl = cmd_exec("/sbin/sysctl -a")
    sysctl_basic(sysctl)
    sysctl_grsec(sysctl)
  end

  def check_cpu
    if grep("nx", { cmd: "cat /proc/cpuinfo" }, true)
      print_good "CPU supports NX"
    else
      print_status "CPU does not support NX"
    end
  end

  def sysctl_basic(data)
    if grep("kernel.randomize_va_space = 1", { string: data }, true)
      #  Make the addresses of mmap base, stack and VDSO page randomized.
      #  This, among other things, implies that shared libraries will be loaded to
      #  random addresses. Also for PIE-linked binaries, the location of code start
      #  is randomized. Heap addresses are *not* randomized.
      print_status "kernel: kernel.randomize_va_space = 1: mmap base, stack and VDSO page randomized, Heap addresses are *not* randomized"
    end
    if grep("kernel.randomize_va_space = 2", { string: data }, true)
      #  Make the addresses of mmap base, heap, stack and VDSO page randomized.
      #  This, among other things, implies that shared libraries will be loaded to random
      #  addresses. Also for PIE-linked binaries, the location of code start is randomized.
      print_good "kernel: kernel.randomize_va_space = 2: mmap base, heap, stack and VDSO page randomized"
    end
    if grep("kernel.randomize_va_space = 0", { string: data }, true)
      print_status "kernel: kernel.randomize_va_space = 0: No randomizing of addresses (mmap base, heap, stack and VDSO page are *not* random)"
    end
    if grep("fs.suid_dumpable = 1", { string: data }, true)
      print_status "kernel: fs.suid_dumpable = 1: setuid programs can perform core dumps"
    end
  end

  def sysctl_grsec(data)
    out = grep("kernel.grsecurity", string: data)
    return if out.empty?
    out.each do |line|
      if line.match "=.*1"
        print_good "Grsecurity setting enabled: #{line}"
      elsif line.match "permission denied on key"
        print_good "Grsecurity setting is hidden: #{line}"
      elsif line.match "=.*0"
        print_status "Grsecurity setting disabled: #{line}"
      else
        print_good "Grsecurity setting unkown: #{line}"
      end
    end
  end

  def get_config
    if readable?("/proc/config.gz")
      if installed?("zcat")
        conf = cmd_exec("zcat /proc/config.gz")
        return conf if conf.match("CONF")
      else
        print_error "no zcat installed"
      end
    end
    kernel = cmd_exec 'uname -r'
    file = "/boot/config-#{kernel}"
    if readable?(file)
      conf = read_file(file, false)
      return conf if conf.match("CONF")
    end
    file = "/usr/src/linux-#{kernel}/.config"
    if readable?(file)
      conf = read_file(file, false)
      return conf if conf.match("CONF")
    end
    file = "/etc/kernels/kernel-config-x86_64-#{kernel}"
    if readable?(file)
      conf = read_file(file, false)
      return conf if conf.match("CONF")
    end
    file = "/etc/kernels/kernel-config-x86-#{kernel}"
    if readable?(file)
      conf = read_file(file, false)
      return conf if conf.match("CONF")
    end

    file = "/usr/src/linux/.config"
    if readable?(file)
      conf = read_file(file, false)
      return conf if conf.match("CONF")
    end
    nil
  end

  def check_config
    conf = get_config
    if conf.nil?
      print_error "Could not get the kernel config"
      return
    end
    if grep("CONFIG_CC_STACKPROTECTOR=y", { string: conf }, true)
      print_good "Kernel: GCC stack protector support: enabled"
    else
      print_status "Kernel: GCC stack protector support: disabled"
    end
    if grep("CONFIG_DEBUG_STRICT_USER_COPY_CHECKS=y", { string: conf }, true)
      print_good "Kernel: Strict user copy checks: enabled"
    else
      print_status "Kernel: Strict user copy checks: disabled"
    end
    if grep("CONFIG_DEBUG_RODATA=y", { string: conf }, true)
      print_good "Kernel: Enforce read-only kernel data: enabled"
    else
      print_status "Kernel: Enforce read-only kernel data: disabled"
    end
    if grep("CONFIG_DEBUG_RODATA=y", { string: conf }, true)
      print_good "Kernel: Enforce read-only kernel data: enabled"
    else
      print_status "Kernel: Enforce read-only kernel data: disabled"
    end
    if grep("CONFIG_STRICT_DEVMEM=y", { string: conf }, true)
      print_good "Kernel: Restrict /dev/mem access: enabled"
    else
      print_status "Kernel: Restrict /dev/mem access: disabled"
    end
    if grep("CONFIG_DEVKMEM=y", { string: conf }, true)
      print_good "Kernel: Restrict /dev/kmem access: enabled"
    else
      print_status "Kernel: Restrict /dev/kmem access: disabled"
    end
    if grep("CONFIG_ARCH_RANDOM=y", { string: conf }, true)
      print_good "Kernel: Random number generator enabled"
    else
      print_status "Kernel: Random number generator disabled"
    end
    if grep("CONFIG_AUDITSYSCALL=y", { string: conf }, true) && grep("CONFIG_AUDIT=y", { string: conf }, true)
      print_good "Kernel:  audit support enabled"
    else
      print_status "Kernel: audit support disabled"
    end
    if grep("CONFIG_SYN_COOKIES=y", { string: conf }, true)
      print_good "Kernel:  TCP SYN cookie protection support enabled"
    else
      print_status "Kernel: TCP SYN cookie protection support disabled"
    end
    if grep("CONFIG_PROC_KCORE=y", { string: conf }, true)
      print_status "Kernel: /proc/kcore support enabled (should be disabled)"
    else
      print_good "Kernel: /proc/kcore support disabled"
    end

    # if grep("=y", {:string => conf}, true)
    #   print_good "Kernel:  enabled"
    # else
    #   print_status "Kernel: disabled"
    # end

    if grep("CONFIG_GRKERNSEC=y", { string: conf }, true)
      print_good "Kernel: Grsecurity enabled"
      check_config_grsec(conf)
    end
  end

  def check_config_grsec(conf)
    if grep("CONFIG_GRKERNSEC_HIGH=y", { string: conf }, true)
      print_good "Kernel: High GRKERNSEC profile enabled"
    elsif grep("CONFIG_GRKERNSEC_MEDIUM=y", { string: conf }, true)
      print_status "Kernel: Medium GRKERNSEC profile enabled"
    elsif grep("CONFIG_GRKERNSEC_LOW=y", { string: conf }, true)
      print_status "Kernel: Low GRKERNSEC profile enabled"
    else
      print_status "Kernel: Custom GRKERNSEC profile enabled"
    end

    if grep("CONFIG_PAX_KERNEXEC=y", { string: conf }, true)
      print_good "Kernel: Non-executable kernel pages: enabled"
    else
      print_status "Kernel: Non-executable kernel pages: disabled"
    end
    if grep("CONFIG_PAX_MEMORY_UDEREF=y", { string: conf }, true)
      print_good "Kernel: Prevent userspace pointer deref: enabled"
    else
      print_status "Kernel: Prevent userspace pointer deref: disabled"
    end
    if grep("CONFIG_PAX_REFCOUNT=y", { string: conf }, true)
      print_good "Kernel: Prevent kobject refcount overflow: enabled"
    else
      print_status "Kernel: Prevent kobject refcount overflow: disabled"
    end
    if grep("CONFIG_PAX_USERCOPY=y", { string: conf }, true)
      print_good "Kernel: Bounds check heap object copies: enabled"
    else
      print_status "Kernel: Bounds check heap object copies: disabled"
    end
    if grep("CONFIG_GRKERNSEC_KMEM=y", { string: conf }, true)
      print_good "Kernel: Disable writing to kmem/mem/port: enabled"
    else
      print_status "Kernel: Disable writing to kmem/mem/port: disabled"
    end
    if grep("CONFIG_GRKERNSEC_IO=y", { string: conf }, true)
      print_good "Kernel: Disable privileged I/O: enabled"
    else
      print_status "Kernel: Disable privileged I/O: disabled"
    end
    if grep("CONFIG_GRKERNSEC_MODHARDEN=y", { string: conf }, true)
      print_good "Kernel: Harden module auto-loading:  enabled"
    else
      print_status "Kernel: Harden module auto-loading: disabled"
    end
    if grep("CONFIG_GRKERNSEC_HIDESYM=y", { string: conf }, true)
      print_good "Kernel: Hide kernel symbols: enabled"
    else
      print_status "Kernel: Hide kernel symbols: disabled"
    end
  end

  def check_grsecurity
    if installed?("gradm")
      tool = installed?("gradm")
      out = cmd_exec("#{tool} -S")
      grsecurity?(out)
    end
  end

  def grsecurity?(out)
    if out.match "The RBAC system is currently enabled"
      print_good "Grsecurity RBAC system is currently enabled"
    elsif out.match "Could not open /dev/grsec"
      print_status "No Grsecurity"
    elsif out.match "The RBAC system is currently disabled"
      print_status "Grsecurity RBAC system is currently disabled"
    else
      print_error "gradmin has wrong output: #{out}"
    end
  end

  def selinux?(out)
    if out.match "Enforcing"
      print_good "SELinux is currently enabled: #{out}"
    elsif out.match "Permissive"
      print_status "SELinux is currently disabled: #{out}"
    else
      print_error "getenforce has wrong output: #{out.dump}"
    end
  end

  def check_selinux
    if installed?("getenforce")
      tool = installed?("getenforce")
      out = cmd_exec(tool.to_s)
      selinux?(out)
    end
  end

  def check_appamor
    if installed?("apparmor_status")
      tool = installed?("apparmor_status")
      out = cmd_exec(tool.to_s)
      appamor?(out)
    end
  end

  def appamor?(out)
    if out.match "enforce mode"
      print_good "Appamor is currently enabled: #{out}"
    elsif out.match("Appamor not enabled") || out.match("apparmor filesystem is not mounted") || out.match("apparmor module is not loaded")
      print_status "Appamor is currently disabled: #{out}"
    elsif out.match "apparmor module is loaded"
      print_status "Apparmor kernel module is loaded"
    elsif out.match "You do not have enough privilege to read the profile set"
      print_status "Not enough privilege to read the profile"
    else
      print_error "appamor_status has wrong output: #{out.dump}"
    end
  end
end
